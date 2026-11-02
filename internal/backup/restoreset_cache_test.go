package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Silo-Server/silo-server/internal/blobstore"
)

// countingDestination counts reads of restore-set.tar.
type countingDestination struct {
	Destination
	opens atomic.Int32
}

func (d *countingDestination) Open(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	if strings.HasSuffix(key, "/"+RestoreSetName) {
		d.opens.Add(1)
	}
	return d.Destination.Open(ctx, key)
}

// TestPreviewsShareOneValidatedRestoreSet: validating a restore set reads
// and hashes the whole archive, so previews of one backup, concurrent or
// repeated, read it once; another archive is read on its own.
func TestPreviewsShareOneValidatedRestoreSet(t *testing.T) {
	ctx := context.Background()
	store, err := blobstore.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dest := &countingDestination{Destination: NewStoreDestination(store)}
	svc := New(Options{Destination: dest, KeyCheck: testKeyCheck, ManifestKey: testManifestKey,
		ServerID: func(context.Context) (string, error) { return "server", nil }})
	put := func(id string) {
		index, entries := testRestoreSet()
		index.ServerName = id // each backup's archive differs
		data := buildTar(t, index, entries)
		sum := sha256.Sum256(data)
		m := validTestManifest()
		m.ID = id
		m.Objects = append(m.Objects, ObjectEntry{Name: RestoreSetName, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
		m.RestoreSet = &RestoreSetSummary{FormatVersion: restoreSetVersion, Sections: map[string]int{SectionSettings: 1}}
		manifest, _ := json.Marshal(m)
		for name, body := range map[string][]byte{RestoreSetName: data, ManifestName: manifest} {
			if err := store.Put(ctx, objectKey("server", id, name), body); err != nil {
				t.Fatal(err)
			}
		}
	}
	const first, second = "20261031T040000Z-nightly", "20261030T040000Z-nightly"
	put(first)
	put(second)

	var wg sync.WaitGroup
	sets := make([]*RestoreSet, 8)
	for i := range sets {
		wg.Go(func() {
			rs, _, err := svc.previewSet(ctx, restoreSource{backupID: first}, true)
			if err != nil {
				t.Error(err)
			}
			sets[i] = rs
		})
	}
	wg.Wait()
	if _, _, err := svc.previewSet(ctx, restoreSource{backupID: first}, true); err != nil {
		t.Fatal(err)
	}
	if n := dest.opens.Load(); n != 1 {
		t.Fatalf("previews of one backup read its restore set %d times, want 1", n)
	}
	for _, rs := range sets {
		if rs != sets[0] || len(rs.Libraries.Libraries) != 1 {
			t.Fatal("previews did not share one validated restore set")
		}
	}
	if _, _, err := svc.previewSet(ctx, restoreSource{backupID: second}, true); err != nil {
		t.Fatal(err)
	}
	if n := dest.opens.Load(); n != 2 {
		t.Fatalf("another backup's restore set reads = %d, want 2", n)
	}
}

// TestRestoreSetReadStopsWithItsLastPreview: one preview leaving does not
// fail another waiting on the same read, and the read stops once no preview
// waits on it.
func TestRestoreSetReadStopsWithItsLastPreview(t *testing.T) {
	var c restoreSetCache
	started, stopped := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	load := func(ctx context.Context) (*RestoreSet, error) {
		close(started)
		select {
		case <-release:
			return &RestoreSet{}, nil
		case <-ctx.Done():
			close(stopped)
			return nil, ctx.Err()
		}
	}
	first, cancelFirst := context.WithCancel(t.Context())
	second, cancelSecond := context.WithCancel(t.Context())
	defer cancelSecond()
	results := make(chan error, 2)
	go func() { _, err := c.get(first, "d", load); results <- err }()
	<-started
	go func() { _, err := c.get(second, "d", load); results <- err }()
	for deadline := time.Now().Add(10 * time.Second); ; {
		c.mu.Lock()
		joined := c.reading["d"] != nil && c.reading["d"].waiters == 2
		c.mu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second preview never joined the read")
		}
		runtime.Gosched()
	}
	cancelFirst()
	if err := <-results; !errors.Is(err, context.Canceled) {
		t.Fatalf("the preview that left = %v, want canceled", err)
	}
	select {
	case <-stopped:
		t.Fatal("the read stopped while another preview waited on it")
	default:
	}
	cancelSecond()
	if err := <-results; !errors.Is(err, context.Canceled) {
		t.Fatalf("the last preview = %v, want canceled", err)
	}
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the read went on after its last preview left")
	}
}
