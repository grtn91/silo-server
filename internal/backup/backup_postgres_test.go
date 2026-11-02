package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

	"github.com/Silo-Server/silo-server/internal/auth"
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
	// A signing key, which no restore brings back (rotatedSettings).
	setSetting(t, pool, settings, settingJWTSecret, "backup-jwt-"+suffix)
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
	// A browser push subscription, which a full restore also takes from the
	// live server.
	exec(`INSERT INTO web_push_subscriptions (id, user_id, profile_id, endpoint, p256dh, auth, device_name, enabled, consecutive_failures, created_at, updated_at)
		VALUES ($1, $2, $3, 'https://push.example.test/'||$1, 'key', 'auth', 'Browser', true, 0, now(), now())`, "push-"+suffix, userID, profileID)
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
	manifestKey, err := secret.BackupManifestKey(masterKey)
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
		Locker:      PostgresLocker{Pool: pool},
		ServerID:    func(context.Context) (string, error) { return serverID, nil },
		KeyCheck:    keyCheck,
		ManifestKey: manifestKey,
		FindTools:   func(context.Context) (Tools, error) { return tools, nil },
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
		Validate: ValidateOptions{KeyCheck: keyCheck, ManifestKey: manifestKey}, Into: into, BlobsInto: blobsInto,
	}); err != nil {
		t.Fatal(err)
	}
	checkManifestTampering(t, src, manifestKey, keyCheck)

	in, err := loader.Inspect(ctx, into)
	if err != nil {
		t.Fatal(err)
	}
	// Everything the manifest counts, less the storage identities, the
	// signing keys, and the API keys the restore cleared.
	var signingKeys int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM server_settings WHERE key = ANY($1)`, rotatedSettingKeys()).Scan(&signingKeys); err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(src.Manifest.Tables)
	for i := range want {
		switch want[i].Name {
		case "server_settings":
			want[i].Rows -= int64(len(storageIdentities)) + signingKeys
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

// checkManifestTampering: a backup whose manifest was changed after it was
// written, here an object's checksum rewritten to match other bytes, is
// refused before anything reads its objects.
func checkManifestTampering(t *testing.T, src *Source, manifestKey []byte, keyCheck string) {
	t.Helper()
	path := filepath.Join(src.Dir, ManifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(path, data, 0o600) })
	m, err := ParseManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	m.Objects[0].SHA256 = strings.Repeat("0", 64)
	changed, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, err := OpenSource(src.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := tampered.Validate(t.Context(), ValidateOptions{KeyCheck: keyCheck, ManifestKey: manifestKey}); !errors.Is(err, ErrManifestTampered) {
		t.Fatalf("validating a changed manifest = %v, want ErrManifestTampered", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
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
	// the backed-up account, and one for an account the backup lacks; the
	// browser that subscribed to push notifications is removed.
	exec(`DELETE FROM api_keys WHERE user_id = $1`, userID)
	exec(`DELETE FROM web_push_subscriptions WHERE user_id = $1`, userID)
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
	var subscriptions int
	if err := restored.QueryRow(ctx, `SELECT count(*) FROM web_push_subscriptions WHERE user_id = $1`, userID).Scan(&subscriptions); err != nil || subscriptions != 0 {
		t.Fatalf("restored %d push subscriptions removed since the backup (%v), want none", subscriptions, err)
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
	checkCarryInvitation(t, loader, pool, dsn, into, restored, "invite-"+suffix)
	checkStricterFlags(t, loader, pool, dsn, into, restored, userID)
}

// checkStricterFlags: an account an admin disabled since the backup, and a
// sign-in provider turned off since, stay off after a full restore, with
// the account's required password change; each is reported. A switch the
// live server has at the looser value takes the backup's.
func checkStricterFlags(t *testing.T, loader PGLoader, pool *pgxpool.Pool, dsn, into string, restored *pgxpool.Pool, userID int64) {
	t.Helper()
	ctx := t.Context()
	var username string
	if err := pool.QueryRow(ctx, `UPDATE users SET enabled = false, password_change_required = true WHERE id = $1 RETURNING username`, userID).Scan(&username); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `UPDATE users SET enabled = true, password_change_required = false WHERE id = $1`, userID)
	}()
	if _, err := restored.Exec(ctx, `UPDATE users SET enabled = true, password_change_required = false WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	// One sign-in provider, off here and on in the backup; another plugin,
	// off here, that signs no one in.
	install := func(db *pgxpool.Pool, id int64, pluginID string, enabled bool) int64 {
		if id == 0 {
			if err := db.QueryRow(ctx, `INSERT INTO plugin_installations (plugin_id, version, install_path, enabled) VALUES ($1, '1.0.0', '/plugins/x', $2) RETURNING id`, pluginID, enabled).Scan(&id); err != nil {
				t.Fatal(err)
			}
			return id
		}
		if _, err := db.Exec(ctx, `INSERT INTO plugin_installations (id, plugin_id, version, install_path, enabled) VALUES ($1, $2, '1.0.0', '/plugins/x', $3)`, id, pluginID, enabled); err != nil {
			t.Fatal(err)
		}
		return id
	}
	provider := install(pool, 0, "sso-provider", false)
	install(restored, provider, "sso-provider", true)
	other := install(pool, 0, "other-plugin", false)
	install(restored, other, "other-plugin", true)
	if _, err := pool.Exec(ctx, `INSERT INTO plugin_auth_bindings (plugin_installation_id, capability_id) VALUES ($1, 'sso')`, provider); err != nil {
		t.Fatal(err)
	}
	carried, err := loader.CarryCredentials(ctx, into, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var enabled, mustChange, providerOn, otherOn bool
	if err := restored.QueryRow(ctx, `SELECT enabled, password_change_required, (SELECT enabled FROM plugin_installations WHERE id = $2),
		(SELECT enabled FROM plugin_installations WHERE id = $3) FROM users WHERE id = $1`, userID, provider, other).Scan(&enabled, &mustChange, &providerOn, &otherOn); err != nil {
		t.Fatal(err)
	}
	if enabled || !mustChange || providerOn || !otherOn {
		t.Fatalf("restored account enabled %v, must change its password %v; provider on %v, other plugin on %v", enabled, mustChange, providerOn, otherOn)
	}
	for _, want := range []string{"account " + username + " kept disabled", "account " + username + " still must change its password", "sign-in provider sso-provider kept off"} {
		if !slices.Contains(carried.Stricter, want) {
			t.Fatalf("reported %v, want %q", carried.Stricter, want)
		}
	}
}

// checkCarryInvitation: a pending invitation is dropped when the account it
// would create gets more under the restored data than live (its default
// group allowed downloads in the backup and does not now), and kept when
// the policies match.
func checkCarryInvitation(t *testing.T, loader PGLoader, pool *pgxpool.Pool, dsn, into string, restored *pgxpool.Pool, tokenHash string) {
	t.Helper()
	ctx := t.Context()
	var id int64
	var allowed bool
	if err := pool.QueryRow(ctx, `SELECT i.id, g.download_allowed FROM invitations i, access_groups g WHERE i.token_hash = $1 AND g.is_default`, tokenHash).Scan(&id, &allowed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `UPDATE access_groups SET download_allowed = $1 WHERE is_default`, allowed)
	})
	setDownloads := func(db *pgxpool.Pool, allow bool) {
		t.Helper()
		if _, err := db.Exec(ctx, `UPDATE access_groups SET download_allowed = $1 WHERE is_default`, allow); err != nil {
			t.Fatal(err)
		}
	}
	invited := func() int {
		t.Helper()
		var n int
		if err := restored.QueryRow(ctx, `SELECT count(*) FROM invitations WHERE token_hash = $1`, tokenHash).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	setDownloads(pool, false)
	setDownloads(restored, true)
	carried, err := loader.CarryCredentials(ctx, into, dsn)
	want := fmt.Sprintf("invitation %d", id)
	if err != nil || !slices.Contains(carried.Dropped, want) || invited() != 0 {
		t.Fatalf("carried %+v (%v), want %q dropped: its group allowed downloads in the backup", carried, err, want)
	}
	setDownloads(restored, false)
	if carried, err = loader.CarryCredentials(ctx, into, dsn); err != nil || slices.Contains(carried.Dropped, want) || invited() != 1 {
		t.Fatalf("carried %+v (%v), want the invitation kept under the same policy", carried, err)
	}
	// The group stopped allowing the permissions a new account gets by
	// default (auth.NewUserPermissions) after the backup.
	var permissions []string
	if err := pool.QueryRow(ctx, `SELECT allowed_permissions FROM access_groups WHERE is_default`).Scan(&permissions); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `UPDATE access_groups SET allowed_permissions = $1 WHERE is_default`, permissions)
	})
	setPermissions := func(db *pgxpool.Pool, allowed []string) {
		t.Helper()
		if _, err := db.Exec(ctx, `UPDATE access_groups SET allowed_permissions = $1 WHERE is_default`, allowed); err != nil {
			t.Fatal(err)
		}
	}
	setPermissions(pool, []string{})
	setPermissions(restored, auth.DefaultUserPermissions())
	if carried, err = loader.CarryCredentials(ctx, into, dsn); err != nil || !slices.Contains(carried.Dropped, want) || invited() != 0 {
		t.Fatalf("carried %+v (%v), want %q dropped: its group allowed more permissions in the backup", carried, err, want)
	}
	setPermissions(restored, []string{})
	if carried, err = loader.CarryCredentials(ctx, into, dsn); err != nil || slices.Contains(carried.Dropped, want) || invited() != 1 {
		t.Fatalf("carried %+v (%v), want the invitation kept once the permissions match", carried, err)
	}
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
	if left != len(rotatedSettings) || !strings.Contains(out.String(), secretKey) || strings.Contains(out.String(), "enter them again after Silo starts: auth.jwt_secret") {
		t.Fatalf("%d encrypted settings left, want only the new signing keys; output %q must name %s and not the signing key", left, out.String(), secretKey)
	}
	// The signing key is a new one, encrypted with this server's key.
	jwt, err := catalog.NewEncryptedSettingsRepo(catalog.NewServerSettingsRepo(restored), other).Get(ctx, settingJWTSecret)
	if err != nil || jwt == "" || strings.HasPrefix(jwt, "backup-jwt-") {
		t.Fatalf("restored signing key = %q, %v; want a new one", jwt, err)
	}
}

// TestEveryTableIsClassifiedDB: every table of the schema, after the
// migrations, is in exactly one list (secretTables, loggedTables,
// restoredDataTables, serverStateTables), and every listed name is a table,
// so a new table cannot reach a backup or a restore without someone
// deciding whether it is data, server state, a log, or a credential the
// restore leaves out or takes from the live server.
func TestEveryTableIsClassifiedDB(t *testing.T) {
	pool, _ := backuptest.Database(t)
	ctx := t.Context()
	tables, err := collectStrings(ctx, pool, `
		SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]string{}
	add := func(list, name string) {
		if other, ok := listed[name]; ok {
			t.Errorf("%s is in %s and %s", name, other, list)
		}
		listed[name] = list
	}
	for _, table := range secretTables {
		add("secretTables", table.name)
		if (table.handling == secretCarried) != (table.carry != nil) || table.why == "" {
			t.Errorf("secretTables entry %s: a carried table needs a carry spec, every entry a reason", table.name)
		}
	}
	for _, name := range loggedTables {
		add("loggedTables", name)
	}
	for _, name := range restoredDataTables {
		add("restoredDataTables", name)
	}
	for _, name := range serverStateTables {
		add("serverStateTables", name)
	}
	present := map[string]bool{}
	for _, table := range tables {
		present[table] = true
		if _, ok := listed[table]; !ok {
			t.Errorf("table %s is not classified: add it to internal/backup (tables.go or secretTables in credentials.go) as data, "+
				"server state, a log, or a credential a restore leaves out or carries from the live server", table)
		}
	}
	for name, list := range listed {
		if !present[name] {
			t.Errorf("%s names %s, which is not a table", list, name)
		}
	}
	// A security switch kept at its stricter value is a column of a table
	// the restore otherwise restores as the backup has it.
	restoredAsBackedUp := map[string]bool{}
	for _, name := range restoredDataTables {
		restoredAsBackedUp[name] = true
	}
	for _, table := range secretTablesHandled(secretRestored) {
		restoredAsBackedUp[table.name] = true
	}
	for _, f := range stricterFlags {
		var boolean bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2 AND data_type = 'boolean')`, f.table, f.column).Scan(&boolean); err != nil {
			t.Fatal(err)
		}
		if !restoredAsBackedUp[f.table] || !boolean {
			t.Errorf("stricterFlags %s.%s: want a boolean column of a table restored as the backup has it, it is in %q", f.table, f.column, listed[f.table])
		}
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
	settings := catalog.NewEncryptedSettingsRepo(catalog.NewServerSettingsRepo(pool), cipher)
	// The stores as the server opens them: the first write records the
	// storage identity through the settings, and so through the pool.
	stores, _, err := blobstore.Open(ctx, blobstore.Options{Backend: blobstore.BackendLocal, LocalPath: t.TempDir(), Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	store := stores.Operational
	serverID := "one-conn-" + randomHex(t, 4)
	svc := New(Options{
		Pool: pool, DatabaseURL: dsn, Settings: settings,
		Stores: stores, Destination: NewStoreDestination(store),
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

// TestFullRestoresAreSerializedDB: two full restores of one database cannot
// run at once. Each control connection is on the maintenance database, so
// neither preflight sees the other; the restore lock refuses the second
// before it reads the backup or changes anything, names the holder, and
// frees when its holder returns or its connection dies.
func TestFullRestoresAreSerializedDB(t *testing.T) {
	_, dsn := backuptest.Database(t)
	ctx := t.Context()
	live, err := databaseName(dsn)
	if err != nil {
		t.Fatal(err)
	}
	connect := func() *PGControl {
		ctl, err := ConnectControl(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ctl.Close(context.Background()) })
		return ctl
	}
	first, second := connect(), connect()
	unlock, err := first.LockRestore(ctx, live)
	if err != nil {
		t.Fatal(err)
	}
	err = RestoreSwap(ctx, &Source{Manifest: &Manifest{}}, nil, second, SwapOptions{LiveURL: dsn})
	if !errors.Is(err, ErrRestoreRunning) || !strings.Contains(err.Error(), "process ") {
		t.Fatalf("a second restore = %v, want ErrRestoreRunning naming the holder", err)
	}
	other, err := second.LockRestore(ctx, live+"_other")
	if err != nil {
		t.Fatalf("another database's restore: %v", err)
	}
	other(ctx)
	unlock(ctx)
	if _, err := second.LockRestore(ctx, live); err != nil {
		t.Fatalf("after the first returned: %v", err)
	}
	// A restore that dies, still holding it, frees the lock with its
	// connection.
	if err := second.Close(ctx); err != nil {
		t.Fatal(err)
	}
	third := connect()
	if unlock, err := third.LockRestore(ctx, live); err != nil {
		t.Fatalf("after the holder's connection closed: %v", err)
	} else {
		unlock(ctx)
	}
}
