package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Silo-Server/silo-server/internal/blobstore"
	"github.com/Silo-Server/silo-server/internal/secret"
	"github.com/Silo-Server/silo-server/internal/serveridentity"
	"github.com/Silo-Server/silo-server/internal/subtitles"
)

// PGLoader restores dumps with pg_restore and reads databases with pgx.
type PGLoader struct {
	Tools Tools
}

func (l PGLoader) Empty(ctx context.Context, dbURL string) (bool, error) {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	var relations int
	err = conn.QueryRow(ctx, `
		SELECT count(*) FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'
		  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e')`).Scan(&relations)
	return relations == 0, err
}

// Load restores without owners or grants: the restoring role owns everything,
// which is the role Silo then connects as.
func (l PGLoader) Load(ctx context.Context, dbURL, dumpPath string) error {
	conn, err := newLibpqConn(dbURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	cmd := exec.CommandContext(ctx, l.Tools.PgRestore, "--exit-on-error", "--no-owner", "--no-privileges", "--no-password", "--dbname="+conn.Conn, dumpPath) //nolint:gosec // G204: the discovered pg_restore with arguments built here, no shell
	cmd.Env = append(os.Environ(), conn.Env...)
	stderr := &limitedBuffer{limit: stderrLimit}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_restore failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (l PGLoader) ServerID(ctx context.Context, dbURL string) (string, error) {
	rows, err := readSettingsAt(ctx, dbURL, []string{serveridentity.Key})
	if err != nil {
		return "", err
	}
	return rows[serveridentity.Key], nil
}

func (l PGLoader) Inspect(ctx context.Context, dbURL string) (Inspection, error) {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return Inspection{}, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	var in Inspection
	if in.GooseVersion, in.Applied, err = appliedMigrations(ctx, conn); err != nil {
		return Inspection{}, err
	}
	in.Tables, err = tableInventory(ctx, conn)
	return in, err
}

func (l PGLoader) UnbindStorage(ctx context.Context, dbURL string) error {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	_, err = conn.Exec(ctx, `DELETE FROM server_settings WHERE key = ANY($1)`,
		[]string{blobstore.IdentitySettingKey, blobstore.OperationalIdentitySettingKey})
	return err
}

func (l PGLoader) ClearUnreadableSettings(ctx context.Context, dbURL string, cipher *secret.Cipher) ([]string, error) {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	rows, err := conn.Query(ctx, `SELECT key, value FROM server_settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	var unreadable []string
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			rows.Close()
			return nil, err
		}
		if !secret.IsEncrypted(value) {
			continue
		}
		if cipher != nil {
			if _, err := cipher.Decrypt(value, secret.SettingsAAD(key)); err == nil {
				continue
			}
		}
		unreadable = append(unreadable, key)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(unreadable) == 0 {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `DELETE FROM server_settings WHERE key = ANY($1)`, unreadable); err != nil {
		return nil, err
	}
	return unreadable, nil
}

func (l PGLoader) DropSubtitles(ctx context.Context, dbURL string, exists func(context.Context, string) (bool, error)) (int, error) {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	rows, err := conn.Query(ctx, `SELECT id, s3_key FROM downloaded_subtitles WHERE provider <> $1`, subtitles.ProviderUpload)
	if err != nil {
		return 0, err
	}
	type row struct {
		id  int
		key string
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var out row
		return out, r.Scan(&out.id, &out.key)
	})
	if err != nil {
		return 0, err
	}
	var gone []int
	for _, r := range all {
		if exists != nil {
			present, err := exists(ctx, r.key)
			if err != nil {
				return 0, fmt.Errorf("checking %s: %w", r.key, err)
			}
			if present {
				continue
			}
		}
		gone = append(gone, r.id)
	}
	if len(gone) == 0 {
		return 0, nil
	}
	tag, err := conn.Exec(ctx, `DELETE FROM downloaded_subtitles WHERE id = ANY($1)`, gone)
	return int(tag.RowsAffected()), err
}

// PGControl is the swap's control connection to the maintenance database.
type PGControl struct {
	Conn *pgx.Conn
	// Like is the database whose encoding and locale a created
	// database copies, so the restored catalog sorts as the live one did.
	Like string
}

// ConnectControl opens the control connection to the maintenance database
// ("postgres") of the server databaseURL points at.
func ConnectControl(ctx context.Context, databaseURL string) (*PGControl, error) {
	live, err := databaseName(databaseURL)
	if err != nil {
		return nil, err
	}
	maintenance, err := WithDatabase(databaseURL, "postgres")
	if err != nil {
		return nil, err
	}
	conn, err := pgx.Connect(ctx, maintenance)
	if err != nil {
		return nil, fmt.Errorf("connecting to the maintenance database: %w", err)
	}
	return &PGControl{Conn: conn, Like: live}, nil
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

func (c *PGControl) OID(ctx context.Context, name string) (uint32, bool, error) {
	var oid uint32
	err := c.Conn.QueryRow(ctx, `SELECT oid FROM pg_database WHERE datname = $1`, name).Scan(&oid)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return oid, err == nil, err
}

func (c *PGControl) NameOf(ctx context.Context, oid uint32) (string, bool, error) {
	var name string
	err := c.Conn.QueryRow(ctx, `SELECT datname FROM pg_database WHERE oid = $1`, oid).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return name, err == nil, err
}

func (c *PGControl) OtherConnections(ctx context.Context, name string) (int, error) {
	var n int
	err := c.Conn.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, name).Scan(&n)
	return n, err
}

// CheckPrivileges: renaming needs CREATEDB and ownership, and ALLOW_CONNECTIONS
// needs ownership; a superuser has both.
func (c *PGControl) CheckPrivileges(ctx context.Context, live string) error {
	var super, createdb, owner bool
	err := c.Conn.QueryRow(ctx, `
		SELECT r.rolsuper, r.rolcreatedb, pg_has_role(current_user, d.datdba, 'USAGE')
		FROM pg_roles r, pg_database d
		WHERE r.rolname = current_user AND d.datname = $1`, live).Scan(&super, &createdb, &owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("database %s does not exist", live)
	}
	if err != nil {
		return err
	}
	if super || (createdb && owner) {
		return nil
	}
	return fmt.Errorf("the database role needs CREATEDB and ownership of %s to swap it", live)
}

func (c *PGControl) Create(ctx context.Context, name string) error {
	want, err := c.locale(ctx, c.Like)
	if err != nil {
		return fmt.Errorf("reading %s's locale: %w", c.Like, err)
	}
	sql := "CREATE DATABASE " + ident(name) + " TEMPLATE template0 ENCODING " + quoteLiteral(want.encoding) +
		" LC_COLLATE " + quoteLiteral(want.collate) + " LC_CTYPE " + quoteLiteral(want.ctype)
	switch want.provider {
	case "c":
		sql += " LOCALE_PROVIDER libc"
	case "i":
		sql += " LOCALE_PROVIDER icu ICU_LOCALE " + quoteLiteral(want.locale)
		if want.icuRules != "" {
			sql += " ICU_RULES " + quoteLiteral(want.icuRules)
		}
	case "b":
		sql += " LOCALE_PROVIDER builtin BUILTIN_LOCALE " + quoteLiteral(want.locale)
	default:
		return fmt.Errorf("%s uses locale provider %q, which a restore cannot copy", c.Like, want.provider)
	}
	if _, err := c.Conn.Exec(ctx, sql); err != nil {
		return err
	}
	// Sorting and case rules (citext logins, names) must match the live
	// database's, or the swap would change them.
	got, err := c.locale(ctx, name)
	if err != nil {
		return fmt.Errorf("reading %s's locale: %w", name, err)
	}
	if got != want {
		return fmt.Errorf("%s was created with locale %+v, not %s's %+v", name, got, c.Like, want)
	}
	return nil
}

// dbLocale is what decides a database's text sorting and case rules.
type dbLocale struct {
	encoding, collate, ctype, provider, locale, icuRules string
}

// locale reads a database's locale. The ICU or builtin locale column is
// datlocale from PostgreSQL 17 and daticulocale before, read by name.
func (c *PGControl) locale(ctx context.Context, name string) (dbLocale, error) {
	var l dbLocale
	err := c.Conn.QueryRow(ctx, `SELECT pg_encoding_to_char(d.encoding), d.datcollate, d.datctype, d.datlocprovider::text,
			COALESCE(to_jsonb(d)->>'datlocale', to_jsonb(d)->>'daticulocale', ''), COALESCE(to_jsonb(d)->>'daticurules', '')
		FROM pg_database d WHERE d.datname = $1`, name).Scan(&l.encoding, &l.collate, &l.ctype, &l.provider, &l.locale, &l.icuRules)
	return l, err
}

func (c *PGControl) Drop(ctx context.Context, name string) error {
	_, err := c.Conn.Exec(ctx, "DROP DATABASE IF EXISTS "+ident(name)+" WITH (FORCE)")
	return err
}

func (c *PGControl) Rename(ctx context.Context, from, to string) error {
	_, err := c.Conn.Exec(ctx, "ALTER DATABASE "+ident(from)+" RENAME TO "+ident(to))
	return err
}

func (c *PGControl) AllowConnections(ctx context.Context, name string, allow bool) error {
	_, err := c.Conn.Exec(ctx, "ALTER DATABASE "+ident(name)+" WITH ALLOW_CONNECTIONS "+strconv.FormatBool(allow))
	return err
}

func (c *PGControl) Terminate(ctx context.Context, name string) error {
	_, err := c.Conn.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, name)
	return err
}

// restoreLockClass is the first key of the full-restore lock, "SRST": a
// two-key advisory lock never collides with the subsystem's one-key lock
// (SubsystemLockKey). The second key is the live database's name, hashed.
const restoreLockClass = 0x53525354

// LockRestore takes a session advisory lock on the control connection, held
// until unlock or until the connection closes, so a restore that dies
// releases it. Both restores reach the same maintenance database, which
// scopes advisory locks.
func (c *PGControl) LockRestore(ctx context.Context, live string) (func(context.Context), error) {
	var acquired bool
	if err := c.Conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1, hashtext($2))`, int32(restoreLockClass), live).Scan(&acquired); err != nil {
		return nil, fmt.Errorf("taking the restore lock: %w", err)
	}
	if !acquired {
		var holder string
		_ = c.Conn.QueryRow(ctx, `
			SELECT format('process %s, %s, since %s', a.pid, coalesce(nullif(a.application_name, ''), 'no application name'), a.backend_start)
			FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 2 AND l.classid = $1::int4::oid AND l.objid = hashtext($2)::oid
			LIMIT 1`, int32(restoreLockClass), live).Scan(&holder)
		if holder == "" {
			holder = "holder unknown"
		}
		return nil, fmt.Errorf("%w (%s): wait for it to finish, or for the other command to exit, and run this again", ErrRestoreRunning, holder)
	}
	return func(ctx context.Context) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = c.Conn.Exec(ctx, `SELECT pg_advisory_unlock($1, hashtext($2))`, int32(restoreLockClass), live)
	}, nil
}

func (c *PGControl) Close(ctx context.Context) error { return c.Conn.Close(ctx) }

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
