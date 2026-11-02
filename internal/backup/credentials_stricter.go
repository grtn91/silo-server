package backup

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// stricterFlag is a security switch inside a table a full restore otherwise
// restores as the backup has it. The restore keeps the stricter of the
// backup's and the live server's value, so it never turns back on what an
// admin turned off since the backup: a disabled account, a provider that
// signs people in, a required password change.
type stricterFlag struct {
	table, column string
	// stricter is the value that wins: false for a switch that grants
	// access, true for one that requires something of the account.
	stricter bool
	// key is the SQL expression, over a row, that names it besides its id:
	// a restored row is the live one only when both match.
	key string
	// scope limits the live rows that apply; everyRow for all.
	scope string
	// describe names a kept row in the restore's output.
	describe string
	// absentOff also sets the stricter value on a restored row the live
	// server no longer has (removed after the backup), described by
	// describeAbsent: it comes back, but never switched on.
	absentOff      bool
	describeAbsent string
}

// columnEnabled is the switch column most flagged tables name.
const columnEnabled = "enabled"

// The keys a row is matched by.
const (
	accountKey = `lower(coalesce(t.username, t.email, ''))`
	pluginKey  = `t.plugin_id`
)

// stricterFlags are the security switches the restore keeps at their
// stricter value. TestEveryTableIsClassifiedDB requires each column to
// exist in a restored data table. Not listed: what grants access through
// policy rather than a switch (users.role and is_owner, the access group
// and per-account permission columns), which a full restore brings back as
// the backup has them, and switches in credential tables, which the
// restore already carries from the live server (secretTables).
var stricterFlags = []stricterFlag{
	{table: tableUsers, column: columnEnabled, stricter: false, key: accountKey, scope: everyRow,
		describe: `format('account %s kept disabled', t.username)`},
	{table: tableUsers, column: "break_glass", stricter: false, key: accountKey, scope: everyRow,
		describe: `format('account %s kept without break-glass sign-in', t.username)`},
	{table: tableUsers, column: "local_password_login_enabled", stricter: false, key: accountKey, scope: everyRow,
		describe: `format('account %s kept without password sign-in', t.username)`},
	{table: tableUsers, column: "password_change_required", stricter: true, key: accountKey, scope: everyRow,
		describe: `format('account %s still must change its password', t.username)`},
	// Plugins run as the server: one an admin turned off stays off (its
	// carried sign-in links then sign no one in), and one removed since
	// the backup comes back off. Nothing a restore does turns one on.
	{table: "plugin_installations", column: columnEnabled, stricter: false, key: pluginKey, scope: everyRow,
		describe: `format('plugin %s kept off', t.plugin_id)`, absentOff: true,
		describeAbsent: `format('plugin %s restored off: removed after the backup', t.plugin_id)`},
	{table: "plugin_task_bindings", column: columnEnabled, stricter: false, key: `t.plugin_installation_id::text || ':' || t.capability_id`, scope: everyRow,
		describe: `format('plugin task %s kept off', t.capability_id)`},
	// A plugin catalog an admin turned off stays off, and one removed since
	// comes back off, so nothing installs or updates from it.
	{table: "plugin_repositories", column: columnEnabled, stricter: false, key: `t.url`, scope: everyRow,
		describe: `format('plugin catalog %s kept off', t.url)`, absentOff: true,
		describeAbsent: `format('plugin catalog %s restored off: removed after the backup', t.url)`},
}

// liveFlags is what readStricterFlags reads for one flag: the live rows at
// its stricter value, and, for an absentOff flag, every live row, each a
// JSON array of {id, key}.
type liveFlags struct {
	stricter, present string
}

// readStricterFlags reads each flag's live rows in the live snapshot tx.
func readStricterFlags(ctx context.Context, tx pgx.Tx) ([]liveFlags, error) {
	out := make([]liveFlags, len(stricterFlags))
	for i, f := range stricterFlags {
		rows := fmt.Sprintf(`SELECT coalesce(json_agg(json_build_object('id', t.id, 'key', %s)), '[]')::text FROM %s t`, f.key, f.table)
		if err := tx.QueryRow(ctx, rows+fmt.Sprintf(` WHERE t.%s = $1 AND %s`, f.column, f.scope), f.stricter).Scan(&out[i].stricter); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", f.table, f.column, err)
		}
		out[i].present = "[]"
		if f.absentOff {
			if err := tx.QueryRow(ctx, rows).Scan(&out[i].present); err != nil {
				return nil, fmt.Errorf("%s: %w", f.table, err)
			}
		}
	}
	return out, nil
}

// keepStricterFlags sets, in the restored database, each flag of a row
// that is also live at its stricter value, and returns what it kept.
func keepStricterFlags(ctx context.Context, tx pgx.Tx, live []liveFlags) ([]string, error) {
	var kept []string
	for i, f := range stricterFlags {
		// A backup taken before the column existed has nothing to keep;
		// the restored server adds it with its default when it migrates.
		var has bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_attribute
			WHERE attrelid = to_regclass($1) AND attname = $2 AND attnum > 0 AND NOT attisdropped)`, f.table, f.column).Scan(&has); err != nil {
			return nil, err
		}
		if !has {
			continue
		}
		sql := fmt.Sprintf(`UPDATE %[1]s t SET %[2]s = $2 FROM json_to_recordset($1::json) AS l(id bigint, key text)
			WHERE t.id = l.id AND %[3]s = l.key AND t.%[2]s IS DISTINCT FROM $2 RETURNING %[4]s`, f.table, f.column, f.key, f.describe)
		names, err := collectKept(ctx, tx, sql, live[i].stricter, f.stricter)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", f.table, f.column, err)
		}
		kept = append(kept, names...)
		if !f.absentOff {
			continue
		}
		sql = fmt.Sprintf(`UPDATE %[1]s t SET %[2]s = $2 WHERE t.%[2]s IS DISTINCT FROM $2 AND NOT EXISTS (
			SELECT 1 FROM json_to_recordset($1::json) AS l(id bigint, key text) WHERE t.id = l.id AND %[3]s = l.key) RETURNING %[4]s`,
			f.table, f.column, f.key, f.describeAbsent)
		if names, err = collectKept(ctx, tx, sql, live[i].present, f.stricter); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", f.table, f.column, err)
		}
		kept = append(kept, names...)
	}
	return kept, nil
}

// collectKept runs an UPDATE … RETURNING a description of each row.
func collectKept(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
