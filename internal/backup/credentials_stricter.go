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
}

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
	{table: tableUsers, column: "enabled", stricter: false, key: accountKey, scope: everyRow,
		describe: `format('account %s kept disabled', t.username)`},
	{table: tableUsers, column: "break_glass", stricter: false, key: accountKey, scope: everyRow,
		describe: `format('account %s kept without break-glass sign-in', t.username)`},
	{table: tableUsers, column: "local_password_login_enabled", stricter: false, key: accountKey, scope: everyRow,
		describe: `format('account %s kept without password sign-in', t.username)`},
	{table: tableUsers, column: "password_change_required", stricter: true, key: accountKey, scope: everyRow,
		describe: `format('account %s still must change its password', t.username)`},
	// A sign-in provider an admin turned off; its carried sign-in links
	// cannot sign anyone in while it stays off.
	{table: "plugin_installations", column: "enabled", stricter: false, key: pluginKey,
		scope: `(EXISTS (SELECT 1 FROM plugin_auth_bindings b WHERE b.plugin_installation_id = t.id)
			OR EXISTS (SELECT 1 FROM plugin_capabilities c WHERE c.plugin_installation_id = t.id AND c.capability_type = 'auth_provider.v1'))`,
		describe: `format('sign-in provider %s kept off', t.plugin_id)`},
}

// readStricterFlags reads, in the live snapshot tx, each flag's live rows
// at the stricter value as a JSON array of {id, key}.
func readStricterFlags(ctx context.Context, tx pgx.Tx) ([]string, error) {
	out := make([]string, len(stricterFlags))
	for i, f := range stricterFlags {
		sql := fmt.Sprintf(`SELECT coalesce(json_agg(json_build_object('id', t.id, 'key', %s)), '[]')::text
			FROM %s t WHERE t.%s = $1 AND %s`, f.key, f.table, f.column, f.scope)
		if err := tx.QueryRow(ctx, sql, f.stricter).Scan(&out[i]); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", f.table, f.column, err)
		}
	}
	return out, nil
}

// keepStricterFlags sets, in the restored database, each flag of a row
// that is also live at its stricter value, and returns what it kept.
func keepStricterFlags(ctx context.Context, tx pgx.Tx, live []string) ([]string, error) {
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
		rows, err := tx.Query(ctx, sql, live[i], f.stricter)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", f.table, f.column, err)
		}
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", f.table, f.column, err)
		}
		kept = append(kept, names...)
	}
	return kept, nil
}
