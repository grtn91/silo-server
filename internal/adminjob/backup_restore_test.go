package adminjob

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestBackupRestoreFencingDB: a restore item commits only while its job is
// running under the worker's claim, and stale recovery cannot slip between
// the check and the commit. A stale restore is marked failed as interrupted,
// never requeued, keeping the report of what committed; the worker that lost
// it cannot write afterwards.
func TestBackupRestoreFencingDB(t *testing.T) {
	r := lifecycleRepo(t)
	ctx := t.Context()
	userID := lifecycleUser(t, r, "restore-fence")
	created, err := r.Create(ctx, CreateJobInput{JobType: JobTypeBackupRestore, CreatedByUserID: userID, RequestPayload: map[string]string{"backup_id": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = r.pool.Exec(context.Background(), `DELETE FROM admin_jobs WHERE id = $1`, created.ID) })
	if _, err := r.Create(ctx, CreateJobInput{JobType: JobTypeBackupRestore, CreatedByUserID: userID}); !errors.Is(err, ErrActiveJobConflict) {
		t.Fatalf("a second active restore = %v, want ErrActiveJobConflict", err)
	}
	job, err := r.ClaimNextQueuedByTypes(ctx, []string{JobTypeBackupRestore})
	if err != nil || job == nil || job.ID != created.ID {
		t.Fatalf("claim = %+v, %v", job, err)
	}
	worker := r.withClaim(job)
	makeStale := func() {
		t.Helper()
		if _, err := r.pool.Exec(ctx, `UPDATE admin_jobs SET heartbeat_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, job.ID); err != nil {
			t.Fatal(err)
		}
	}
	staleBefore := func() time.Time { return time.Now().UTC().Add(-2 * time.Minute) }

	// An item holding the row lock: recovery waits for its commit, then sees
	// the heartbeat the commit wrote and leaves the job running.
	makeStale()
	locked, release := make(chan struct{}), make(chan struct{})
	fenced := make(chan error, 1)
	go func() {
		fenced <- worker.RunFenced(ctx, job.ID, func(tx pgx.Tx) (FencedUpdate, error) {
			close(locked)
			<-release
			return FencedUpdate{Result: map[string]int{"items": 1}, Current: 1, Total: 2, Message: "item 1"}, nil
		})
	}()
	<-locked
	recovered := make(chan error, 1)
	go func() {
		_, err := r.RequeueStaleRunning(context.Background(), staleBefore())
		recovered <- err
	}()
	select {
	case <-recovered:
		t.Fatal("stale recovery did not wait for the item's row lock")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-fenced; err != nil {
		t.Fatal(err)
	}
	if err := <-recovered; err != nil {
		t.Fatal(err)
	}
	current, err := r.GetByID(ctx, job.ID)
	if err != nil || current.Status != StatusRunning || current.ProgressCurrent != 1 {
		t.Fatalf("after a committed item the job is %+v, %v; want still running", current, err)
	}

	// An item that outlasts the stale window: its commit writes the
	// heartbeat at the commit's time, not its transaction's start, so the
	// recovery waiting behind it does not find the job stale.
	checkLongItem(t, r, worker, job.ID)

	// A worker that stopped heartbeating is interrupted, not requeued.
	makeStale()
	if _, err := r.RequeueStaleRunning(ctx, staleBefore()); err != nil {
		t.Fatal(err)
	}
	current, err = r.GetByID(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]int
	_ = json.Unmarshal(current.ResultPayload, &report)
	if current.Status != StatusFailed || current.ErrorMessage != BackupRestoreInterrupted || report["items"] != 1 {
		t.Fatalf("stale restore = status %s error %q report %v; want failed, interrupted, report kept", current.Status, current.ErrorMessage, report)
	}

	// The slow original worker cannot commit another item.
	called := false
	err = worker.RunFenced(ctx, job.ID, func(pgx.Tx) (FencedUpdate, error) {
		called = true
		return FencedUpdate{}, nil
	})
	if !errors.Is(err, ErrJobNotFound) || called {
		t.Fatalf("fenced write after interruption = %v (ran %v), want ErrJobNotFound without running", err, called)
	}
}

// checkLongItem runs an item that holds the job row past a stale window
// that starts after the item did, with an ordinary heartbeat and then
// recovery waiting on its row lock.
func checkLongItem(t *testing.T, r *Repository, worker *Repository, id string) {
	t.Helper()
	ctx := t.Context()
	locked, release := make(chan struct{}), make(chan struct{})
	fenced := make(chan error, 1)
	go func() {
		fenced <- worker.RunFenced(ctx, id, func(pgx.Tx) (FencedUpdate, error) {
			close(locked)
			<-release
			return FencedUpdate{Result: map[string]int{"items": 1}, Current: 1, Total: 2, Message: "item 1, again"}, nil
		})
	}()
	<-locked
	// An ordinary heartbeat that began during the item waits on the row
	// first, then recovery: neither may take the job for stale.
	waitFor := func(n int) {
		t.Helper()
		for waiting := 0; waiting < n; {
			if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
				WHERE wait_event_type = 'Lock' AND query LIKE '%UPDATE admin_jobs%'`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
	}
	beat := make(chan error, 1)
	go func() { beat <- worker.TouchHeartbeat(context.Background(), id) }()
	waitFor(1)
	// Anything older than now is stale: the item's transaction and the
	// waiting heartbeat's statement both began before it.
	var window time.Time
	if err := r.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&window); err != nil {
		t.Fatal(err)
	}
	recovered := make(chan error, 1)
	go func() {
		_, err := r.RequeueStaleRunning(context.Background(), window)
		recovered <- err
	}()
	waitFor(2)
	close(release)
	if err := <-fenced; err != nil {
		t.Fatal(err)
	}
	if err := <-beat; err != nil {
		t.Fatal(err)
	}
	if err := <-recovered; err != nil {
		t.Fatal(err)
	}
	current, err := r.GetByID(ctx, id)
	if err != nil || current.Status != StatusRunning || current.Message != "item 1, again" {
		t.Fatalf("after an item longer than the stale window the job is %+v, %v; want still running", current, err)
	}
}
