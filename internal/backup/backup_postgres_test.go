package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Silo-Server/silo-server/internal/backup/backuptest"
	"github.com/Silo-Server/silo-server/internal/blobstore"
	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/config"
	"github.com/Silo-Server/silo-server/internal/secret"
)

// testDB opens SILO_TEST_DATABASE_URL, a migrated database other tests share.
// A test that runs pg_dump or pg_restore uses backuptest.Database instead:
// other packages' tests create and drop schemas here while a dump reads them.
func testDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("SILO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SILO_TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, dsn
}

func testTools(t *testing.T) Tools {
	t.Helper()
	tools, err := FindTools(t.Context())
	if err != nil {
		t.Skipf("PostgreSQL client tools: %v", err)
	}
	return tools
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// createDatabase makes an empty database on the test server and drops it at
// the end of the test.
func createDatabase(t *testing.T, pool *pgxpool.Pool, dsn string) string {
	t.Helper()
	name := "silo_backup_test_" + randomHex(t, 4)
	if _, err := pool.Exec(t.Context(), "CREATE DATABASE "+ident(name)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident(name)+" WITH (FORCE)")
	})
	url, err := WithDatabase(dsn, name)
	if err != nil {
		t.Fatal(err)
	}
	return url
}

// setSetting writes a setting for the test and puts the previous state back.
// Other packages' tests share the database, so the keys a test sets are ones
// nothing else reads.
func setSetting(t *testing.T, pool *pgxpool.Pool, settings *catalog.EncryptedSettingsRepo, key, value string) {
	t.Helper()
	ctx := t.Context()
	var previous string
	err := pool.QueryRow(ctx, `SELECT value FROM server_settings WHERE key = $1`, key).Scan(&previous)
	existed := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	if err := settings.Set(ctx, key, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_, _ = pool.Exec(context.Background(), `UPDATE server_settings SET value = $2 WHERE key = $1`, key, previous)
			return
		}
		_, _ = pool.Exec(context.Background(), `DELETE FROM server_settings WHERE key = $1`, key)
	})
}

// roundTripSeed is what the round trip writes before backing up.
var storageIdentities = []string{blobstore.IdentitySettingKey, blobstore.OperationalIdentitySettingKey}

type roundTripSeed struct {
	secretKey, secretValue string
	missingKey             string
	blobs                  map[string][]byte
	userID                 int64
	// leftOut is a stored blob the backup must not copy.
	leftOut string
}

// seedRoundTrip writes an encrypted setting, recorded storage identities, a
// branding asset, a library with a poster, a library whose poster is gone,
// and a profile with an uploaded avatar, all removed again when the test
// ends.
func seedRoundTrip(t *testing.T, pool *pgxpool.Pool, settings *catalog.EncryptedSettingsRepo, store blobstore.Store) roundTripSeed {
	t.Helper()
	ctx := t.Context()
	suffix := randomHex(t, 4)
	seed := roundTripSeed{secretKey: "s3.operational_token_secret", secretValue: "token-" + suffix, missingKey: "library-posters/" + suffix + "-gone.jpg"}
	setSetting(t, pool, settings, seed.secretKey, seed.secretValue)
	setSetting(t, pool, settings, "branding.mark_light_ref", suffix+".webp")
	// The source's recorded stores, which a separate restore must not keep.
	for _, key := range storageIdentities {
		setSetting(t, pool, settings, key, "local|/elsewhere")
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var folderID, userID int64
	if err := pool.QueryRow(ctx, `SELECT (SELECT COALESCE(MAX(id), 0) + 1000 FROM media_folders), (SELECT COALESCE(MAX(id), 0) + 1000 FROM users)`).Scan(&folderID, &userID); err != nil {
		t.Fatal(err)
	}
	posterKey := "library-posters/" + suffix + ".jpg"
	exec(`INSERT INTO media_folders (id, type, name, poster_path) VALUES ($1, 'movies', $2, $3), ($4, 'movies', $5, $6)`,
		folderID, "Backup test "+suffix, posterKey, folderID+1, "Backup test gone "+suffix, seed.missingKey)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM media_folders WHERE id IN ($1, $2)`, folderID, folderID+1)
	})
	profileID := "backup-test-" + suffix
	avatarKey := "profile-avatars/" + profileID + "/original.webp"
	exec(`INSERT INTO users (id, role, username) VALUES ($1, 'user', $2)`, userID, "backup-test-"+suffix)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) })
	exec(`INSERT INTO user_profiles (id, user_id, name, avatar) VALUES ($1, $2, 'Backup', $3)`, profileID, userID, "upload:"+avatarKey)
	// A sign-in the restore must not bring back (secretTables, secretLeftOut).
	exec(`INSERT INTO auth_sessions (id, user_id, expires_at) VALUES ($1, $2, now() + interval '1 day')`, "backup-test-"+suffix, userID)
	// An API key, which a full restore replaces with the live ones and a
	// separate restore leaves out (secretTables, secretCarried).
	exec(`INSERT INTO api_keys (user_id, label, key_hash) VALUES ($1, 'in backup', encode(sha256(convert_to($2, 'UTF8')), 'hex'))`, userID, "in-backup-"+suffix)
	seed.userID = userID
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM user_profiles WHERE id = $1`, profileID) })
	// An uploaded subtitle, which the backup keeps with
	// backup.include_subtitles off, and a provider's, which it leaves out.
	setSetting(t, pool, settings, config.BackupIncludeSubtitlesSettingKey, "false")
	uploadedSub, providerSub := "subtitles/"+suffix+"-upload.srt", "subtitles/"+suffix+"-provider.srt"
	exec(`INSERT INTO media_items (content_id, type, title) VALUES ($1, 'movie', 'Backup subtitles')`, "backup-test-"+suffix)
	exec(`INSERT INTO media_files (id, media_folder_id, file_path, content_id) VALUES ($1, $2, $3, $4)`,
		folderID, folderID, "/backup-test/"+suffix+".mkv", "backup-test-"+suffix)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM media_items WHERE content_id = $1`, "backup-test-"+suffix)
	})
	exec(`INSERT INTO downloaded_subtitles (media_file_id, provider, language, format, s3_key) VALUES ($1, 'upload', 'en', 'srt', $2), ($1, 'opensubtitles', 'en', 'srt', $3)`,
		folderID, uploadedSub, providerSub)
	if err := store.Put(ctx, providerSub, []byte("provider "+suffix)); err != nil {
		t.Fatal(err)
	}
	seed.leftOut = providerSub
	seed.blobs = map[string][]byte{
		uploadedSub: []byte("uploaded subtitle " + suffix),
		posterKey:   []byte("poster " + suffix),
		"branding/mark-light/" + suffix + ".webp": []byte("mark " + suffix),
		avatarKey: []byte("avatar " + suffix),
		"profile-avatars/" + profileID + "/w256.webp": []byte("avatar display " + suffix),
	}
	for key, data := range seed.blobs {
		if err := store.Put(ctx, key, data); err != nil {
			t.Fatal(err)
		}
	}
	return seed
}

// TestBackupRestoreRoundTripDB is the full restore round trip: a seeded
// database with blobs and an encrypted setting is backed up, restored in
// separate mode into an empty database and a blob directory, and the restored
// inventory, blobs, and decrypted value are compared with the source. The
// drill refuses a database in use, and another SECRET_KEY refuses to restore.
func TestBackupRestoreRoundTripDB(t *testing.T) {
	pool, dsn := backuptest.Database(t)
	tools := testTools(t)
	ctx := t.Context()
	masterKey := []byte("round-trip-test-key-0123456789abcdef")
	cipher, err := secret.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	keyCheck, err := secret.KeyCheckValue(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	settings := catalog.NewEncryptedSettingsRepo(catalog.NewServerSettingsRepo(pool), cipher)
	root := t.TempDir()
	store, err := blobstore.NewFilesystem(root)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedRoundTrip(t, pool, settings, store)

	serverID := "round-trip-" + randomHex(t, 4)
	svc := New(Options{
		Pool: pool, DatabaseURL: dsn, Settings: settings,
		Stores: blobstore.Stores{Assets: store, Operational: store}, Destination: NewStoreDestination(store),
		Locker:    PostgresLocker{Pool: pool},
		ServerID:  func(context.Context) (string, error) { return serverID, nil },
		KeyCheck:  keyCheck,
		FindTools: func(context.Context) (Tools, error) { return tools, nil },
	})
	held, err := svc.opts.Locker.TryLock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Backup(ctx, held, KindManual, "", nil)
	held.Release(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusCompleteWithWarnings || len(result.MissingBlobs) != 1 || result.MissingBlobs[0].Key != seed.missingKey {
		t.Fatalf("backup result = %+v, want complete with warnings naming %s", result, seed.missingKey)
	}

	src, err := OpenSource(filepath.Join(root, "backups", serverID, result.ID))
	if err != nil {
		t.Fatal(err)
	}
	into := createDatabase(t, pool, dsn)
	blobsInto := t.TempDir()
	loader := PGLoader{Tools: tools}
	if _, err := RestoreSeparate(ctx, src, loader, SeparateOptions{
		Validate: ValidateOptions{KeyCheck: keyCheck}, Into: into, BlobsInto: blobsInto,
	}); err != nil {
		t.Fatal(err)
	}

	in, err := loader.Inspect(ctx, into)
	if err != nil {
		t.Fatal(err)
	}
	// Everything the manifest counts, less the storage identities and the
	// API keys the restore cleared.
	want := slices.Clone(src.Manifest.Tables)
	for i := range want {
		switch want[i].Name {
		case "server_settings":
			want[i].Rows -= int64(len(storageIdentities))
		case "api_keys":
			want[i].Rows = 0
		}
	}
	if in.GooseVersion != src.Manifest.GooseVersion || !slices.Equal(in.Tables, want) {
		t.Fatalf("restored inventory %d %+v, want %d %+v", in.GooseVersion, in.Tables, src.Manifest.GooseVersion, want)
	}
	if len(src.Manifest.AppliedMigrations) == 0 || !slices.Equal(in.Applied, src.Manifest.AppliedMigrations) {
		t.Fatalf("restored applied migrations %v, manifest %v", in.Applied, src.Manifest.AppliedMigrations)
	}
	restoredPool, err := pgxpool.New(ctx, into)
	if err != nil {
		t.Fatal(err)
	}
	defer restoredPool.Close()
	checkRestoredFiles(t, seed, blobsInto, restoredPool)
	checkCredentials(t, loader, pool, dsn, into, restoredPool, seed.userID)
	restoredSettings := catalog.NewEncryptedSettingsRepo(catalog.NewServerSettingsRepo(restoredPool), cipher)
	if got, err := restoredSettings.Get(ctx, seed.secretKey); err != nil || got != seed.secretValue {
		t.Fatalf("restored encrypted setting = %q, %v; want %q", got, err, seed.secretValue)
	}

	if err := VerifyBackup(ctx, src, loader, into, ValidateOptions{KeyCheck: keyCheck}, io.Discard); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("verify into a used database = %v, want refusal", err)
	}
	checkAnotherKey(t, src, loader, pool, dsn, seed.secretKey)
}

// checkRestoredFiles: every blob the backup holds is restored, and a
// provider subtitle the setting left out is neither restored nor listed.
func checkRestoredFiles(t *testing.T, seed roundTripSeed, blobsInto string, restored *pgxpool.Pool) {
	t.Helper()
	for key, want := range seed.blobs {
		got, err := os.ReadFile(filepath.Join(blobsInto, filepath.FromSlash(key)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restored blob %s = %q, %v; want %q", key, got, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(blobsInto, filepath.FromSlash(seed.leftOut))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("restored %s, a provider subtitle the setting leaves out (%v)", seed.leftOut, err)
	}
	var omitted int
	if err := restored.QueryRow(t.Context(), `SELECT count(*) FROM downloaded_subtitles WHERE s3_key = $1`, seed.leftOut).Scan(&omitted); err != nil || omitted != 0 {
		t.Fatalf("restored %d rows of the subtitle the backup left out (%v), want none", omitted, err)
	}
}

// checkCredentials: a restore brings back no sign-in session. A full
// restore keeps the live server's API keys and pending invitations as they
// are at the swap, not the backup's, and drops a live key whose account is
// not in the backup.
func checkCredentials(t *testing.T, loader PGLoader, pool *pgxpool.Pool, dsn, into string, restored *pgxpool.Pool, userID int64) {
	t.Helper()
	ctx := t.Context()
	var sessions int
	if err := restored.QueryRow(ctx, `SELECT count(*) FROM auth_sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("restored %d sign-in sessions (%v), want none", sessions, err)
	}
	suffix := randomHex(t, 4)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// After the backup: the backed-up key is revoked, one is created for
	// the backed-up account, and one for an account the backup lacks.
	exec(`DELETE FROM api_keys WHERE user_id = $1`, userID)
	exec(`INSERT INTO api_keys (user_id, label, key_hash) VALUES ($1, 'after backup', encode(sha256(convert_to($2, 'UTF8')), 'hex'))`, userID, "live-"+suffix)
	var newUser, keptID int64
	if err := pool.QueryRow(ctx, `INSERT INTO users (role, username) VALUES ('user', $1) RETURNING id`, "after-backup-"+suffix).Scan(&newUser); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, newUser) })
	exec(`INSERT INTO api_keys (user_id, label, key_hash) VALUES ($1, 'new account', encode(sha256(convert_to($2, 'UTF8')), 'hex'))`, newUser, "orphan-"+suffix)
	// A pending invitation, carried too.
	exec(`INSERT INTO invitations (token_hash, invited_by, expires_at, delivery, library_ids)
		VALUES ($1, $2, now() + interval '1 day', 'link', '{}')`, "invite-"+suffix, userID)
	var liveKeys, liveInvitations int
	if err := pool.QueryRow(ctx, `SELECT count(*), max(id) FILTER (WHERE user_id = $1),
		(SELECT count(*) FROM invitations WHERE accepted_at IS NULL AND revoked_at IS NULL) FROM api_keys`, userID).Scan(&liveKeys, &keptID, &liveInvitations); err != nil {
		t.Fatal(err)
	}

	carried, err := loader.CarryCredentials(ctx, into, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var orphan int64
	if err := pool.QueryRow(ctx, `SELECT id FROM api_keys WHERE user_id = $1`, newUser).Scan(&orphan); err != nil {
		t.Fatal(err)
	}
	wantDropped := []string{fmt.Sprintf("API key %d 'new account' (account %d)", orphan, newUser)}
	if carried.Kept["api_keys"] != liveKeys-1 || carried.Kept["invitations"] != liveInvitations || !slices.Equal(carried.Dropped, wantDropped) {
		t.Fatalf("carried %+v, want %d keys and %d invitations kept and dropped %q", carried, liveKeys-1, liveInvitations, wantDropped)
	}
	var invited int
	if err := restored.QueryRow(ctx, `SELECT count(*) FROM invitations WHERE token_hash = $1`, "invite-"+suffix).Scan(&invited); err != nil || invited != 1 {
		t.Fatalf("restored %d copies of the live invitation (%v), want 1", invited, err)
	}
	rows, err := restored.Query(ctx, `SELECT label FROM api_keys WHERE user_id = $1`, userID)
	if err != nil {
		t.Fatal(err)
	}
	if labels, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(labels, []string{"after backup"}) {
		t.Fatalf("restored keys of the backed-up account = %v (%v), want only the live one", labels, err)
	}
	// The next key the restored server creates must not reuse a live id.
	var next int64
	if err := restored.QueryRow(ctx, `INSERT INTO api_keys (user_id, label, key_hash) VALUES ($1, 'next', encode(sha256(convert_to($2, 'UTF8')), 'hex')) RETURNING id`, userID, "next-"+suffix).Scan(&next); err != nil || next <= keptID {
		t.Fatalf("next restored key id %d (%v), want above %d", next, err, keptID)
	}
	checkCarryAuthority(t, loader, pool, dsn, into, restored, userID, keptID, liveKeys)
}

// checkCarryAuthority: a live key is dropped when its account has more
// authority in the restored data than live (an admin there, or every
// library there and one here), and kept when the policies match.
func checkCarryAuthority(t *testing.T, loader PGLoader, pool *pgxpool.Pool, dsn, into string, restored *pgxpool.Pool, userID, keptID int64, liveKeys int) {
	t.Helper()
	ctx := t.Context()
	// An account that was an admin in the backup and is a user here: its
	// live key would carry admin authority, so it is dropped.
	if _, err := restored.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	carried, err := loader.CarryCredentials(ctx, into, dsn)
	if err != nil {
		t.Fatal(err)
	}
	demoted := fmt.Sprintf("API key %d 'after backup' (account %d)", keptID, userID)
	var left int
	if err := restored.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if carried.Kept["api_keys"] != liveKeys-2 || !slices.Contains(carried.Dropped, demoted) || left != 0 {
		t.Fatalf("carried %+v with %d keys left for the demoted account, want its key %q dropped", carried, left, demoted)
	}
	// The same account with the same role, narrowed here to one library
	// since the backup: the restored account sees every library, so its
	// live key is dropped too.
	var library int64
	if err := restored.QueryRow(ctx, `UPDATE users SET role = 'user' WHERE id = $1 RETURNING (SELECT min(id) FROM media_folders)`, userID).Scan(&library); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET library_ids = ARRAY[$2::int] WHERE id = $1`, userID, library); err != nil {
		t.Fatal(err)
	}
	if carried, err = loader.CarryCredentials(ctx, into, dsn); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(carried.Dropped, demoted) {
		t.Fatalf("carried %+v, want the narrowed account's key %q dropped", carried, demoted)
	}
	// Narrowed the same way in the restored data, it keeps its key.
	if _, err := restored.Exec(ctx, `UPDATE users SET library_ids = ARRAY[$2::int] WHERE id = $1`, userID, library); err != nil {
		t.Fatal(err)
	}
	if carried, err = loader.CarryCredentials(ctx, into, dsn); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(carried.Dropped, demoted) || carried.Kept["api_keys"] != liveKeys-1 {
		t.Fatalf("carried %+v, want the key of an account with the same policy kept", carried)
	}
}

// checkAnotherKey: a backup taken with another SECRET_KEY restores only
// with the operator's explicit acceptance, and then without the encrypted
// settings this key cannot read, which Silo could not start on.
func checkAnotherKey(t *testing.T, src *Source, loader PGLoader, pool *pgxpool.Pool, dsn, secretKey string) {
	t.Helper()
	ctx := t.Context()
	other, err := secret.New([]byte("another-test-key-0123456789abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreSeparate(ctx, src, loader, SeparateOptions{
		Validate: ValidateOptions{KeyCheck: "0000-0000-0000-0000"}, Into: createDatabase(t, pool, dsn), DatabaseOnly: true,
	}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("restore with another key = %v, want ErrKeyMismatch", err)
	}
	into := createDatabase(t, pool, dsn)
	var out strings.Builder
	if _, err := RestoreSeparate(ctx, src, loader, SeparateOptions{
		Validate: ValidateOptions{KeyCheck: "0000-0000-0000-0000", AcceptLostCredentials: true}, Cipher: other,
		Into: into, DatabaseOnly: true, Out: &out,
	}); err != nil {
		t.Fatal(err)
	}
	restored, err := pgxpool.New(ctx, into)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var left int
	if err := restored.QueryRow(ctx, `SELECT count(*) FROM server_settings WHERE value LIKE 'enc:%'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 || !strings.Contains(out.String(), secretKey) {
		t.Fatalf("%d unreadable settings left; output %q does not name %s", left, out.String(), secretKey)
	}
}

// secretColumn is a column name that can hold a bearer secret or a public
// capability; notSecretColumn excludes names it matches that never do.
var (
	secretColumn    = `token|secret|slug|key_hash|password|pin_hash|ticket|api_key(_ref|_hash)?$|flow_hash|binder_hash|code_challenge|(^|_)codes?(_hash)?$`
	notSecretColumn = `_codes$|status_code$|warning_code$|failure_code$|token_type$|token_expir|password_login_enabled$|password_change_required$`
)

// TestSecretTablesAreClassifiedDB: every table with a secret-like column is
// in secretTables, so a new credential cannot be restored from a backup
// without someone deciding whether it should be, and every name there is
// a table, so the dump excludes or the restore carries something by it.
func TestSecretTablesAreClassifiedDB(t *testing.T) {
	pool, _ := backuptest.Database(t)
	ctx := t.Context()
	rows, err := pool.Query(ctx, `
		SELECT c.relname::text, string_agg(a.attname::text, ', ' ORDER BY a.attnum)
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
		  AND a.attnum > 0 AND NOT a.attisdropped AND a.attname ~ $1 AND a.attname !~ $2
		GROUP BY c.relname ORDER BY c.relname`, secretColumn, notSecretColumn)
	if err != nil {
		t.Fatal(err)
	}
	classified := map[string]bool{}
	for _, table := range secretTables {
		if classified[table.name] {
			t.Errorf("%s is in secretTables twice", table.name)
		}
		classified[table.name] = true
		var found bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table.name).Scan(&found); err != nil || !found {
			t.Errorf("secretTables names %s, which is not a table (%v)", table.name, err)
		}
		if (table.handling == secretCarried) != (table.carry != nil) || table.why == "" {
			t.Errorf("secretTables entry %s: a carried table needs a carry spec, every entry a reason", table.name)
		}
	}
	for rows.Next() {
		var table, columns string
		if err := rows.Scan(&table, &columns); err != nil {
			t.Fatal(err)
		}
		if !classified[table] {
			t.Errorf("%s has secret-like columns (%s) and is not in secretTables: decide whether a restore leaves it out, carries the live rows, or restores it", table, columns)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// failingDestination fails writes of one object name.
type failingDestination struct {
	Destination
	failName string
}

func (d failingDestination) Put(ctx context.Context, key string, r io.Reader) error {
	if strings.HasSuffix(key, "/"+d.failName) {
		_, _ = io.Copy(io.Discard, r)
		return errors.New("injected write failure")
	}
	return d.Destination.Put(ctx, key, r)
}

// TestBackupWritesManifestLastDB: a backup that fails after the dump leaves a
// folder with no manifest, which listing reports as incomplete and the sweep
// deletes once it is a day old.
func TestBackupWritesManifestLastDB(t *testing.T) {
	pool, dsn := backuptest.Database(t)
	tools := testTools(t)
	ctx := t.Context()
	store, err := blobstore.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 4, 0, 0, 0, time.UTC)
	serverID := "manifest-last-" + randomHex(t, 4)
	opts := Options{
		Pool: pool, DatabaseURL: dsn,
		Stores:      blobstore.Stores{Assets: store, Operational: store},
		Destination: failingDestination{Destination: NewStoreDestination(store), failName: BlobsName},
		Locker:      PostgresLocker{Pool: pool},
		Status:      PostgresStatus{Pool: pool},
		ServerID:    func(context.Context) (string, error) { return serverID, nil },
		FindTools:   func(context.Context) (Tools, error) { return tools, nil },
		Now:         func() time.Time { return now },
	}
	resetStatus := func() { _, _ = pool.Exec(context.Background(), `DELETE FROM backup_status`) }
	resetStatus()
	t.Cleanup(resetStatus)
	failing := New(opts)
	if _, err := backupUnderLock(t, failing, KindNightly); err == nil {
		t.Fatal("backup with a failing blobs.tar write succeeded")
	}
	failedID := FolderName(now, KindNightly)
	if _, err := store.Stat(ctx, objectKey(serverID, failedID, ManifestName)); !errors.Is(err, blobstore.ErrNotFound) {
		t.Fatalf("failed backup wrote a manifest: %v", err)
	}
	if _, err := store.Stat(ctx, objectKey(serverID, failedID, DumpName)); err != nil {
		t.Fatalf("the dump before the failure is gone: %v", err)
	}
	listing, err := failing.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Backups) != 1 || listing.Backups[0].Status != StatusIncomplete {
		t.Fatalf("listing = %+v, want one incomplete folder", listing.Backups)
	}

	// The folder's own objects carry real modification times; the day has
	// to pass for those too, so move the clock well past both.
	opts.Destination = NewStoreDestination(store)
	opts.Now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	result, err := backupUnderLock(t, New(opts), KindNightly)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Swept, []string{failedID}) {
		t.Fatalf("swept %v, want [%s]", result.Swept, failedID)
	}
	if objects, _, _ := store.List(ctx, folderPrefix(serverID, failedID), "", 0); len(objects) != 0 {
		t.Fatalf("swept folder still holds %d objects", len(objects))
	}
}

// backupUnderLock takes the subsystem lock and backs up under it.
func backupUnderLock(t *testing.T, svc *Service, kind Kind) (RunResult, error) {
	t.Helper()
	held, err := svc.opts.Locker.TryLock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release(t.Context())
	return svc.Backup(t.Context(), held, kind, "", nil)
}

// TestBackupAndDeleteWithOnePoolConnectionDB: Silo runs with a database pool
// of one connection. The lock's session is not a pool connection, and status
// writes run on it, so a backup (snapshot transaction, settings reads,
// rotation) and a delete finish instead of waiting for themselves.
func TestBackupAndDeleteWithOnePoolConnectionDB(t *testing.T) {
	_, dsn := backuptest.Database(t)
	tools := testTools(t)
	// A deadlock on the one connection shows as this deadline, not a hang.
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	resetStatus := func() { _, _ = pool.Exec(context.Background(), `DELETE FROM backup_status`) }
	resetStatus()
	t.Cleanup(resetStatus)
	cipher, err := secret.New([]byte("one-connection-test-key-0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := blobstore.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serverID := "one-conn-" + randomHex(t, 4)
	svc := New(Options{
		Pool: pool, DatabaseURL: dsn, Settings: catalog.NewEncryptedSettingsRepo(catalog.NewServerSettingsRepo(pool), cipher),
		Stores: blobstore.Stores{Assets: store, Operational: store}, Destination: NewStoreDestination(store),
		Locker: PostgresLocker{Pool: pool}, Status: PostgresStatus{Pool: pool},
		ServerID:  func(context.Context) (string, error) { return serverID, nil },
		FindTools: func(context.Context) (Tools, error) { return tools, nil },
	})
	result, err := svc.RunTask(ctx, nil)
	if err != nil || result.ID == "" {
		t.Fatalf("backup with one pool connection = %+v, %v", result, err)
	}
	listing, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if listing.LastRun == nil || listing.LastRun.ID != result.ID || listing.LastRun.Status != string(result.Status) || listing.Active != nil {
		t.Fatalf("published status = last %+v, active %+v", listing.LastRun, listing.Active)
	}
	if err := svc.Delete(ctx, result.ID); err != nil {
		t.Fatalf("delete with one pool connection: %v", err)
	}
	if objects, _, _ := store.List(ctx, folderPrefix(serverID, result.ID), "", 0); len(objects) != 0 {
		t.Fatalf("the deleted backup still holds %d objects", len(objects))
	}
}
