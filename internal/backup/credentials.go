package backup

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// credentialTable is a table of long-lived credentials that clients and
// other services present to Silo. A full restore does not bring back the
// backup's rows: a key revoked after the backup would work again, and one
// created since would stop working. It keeps the live server's rows as they
// are right before the swap instead, less those whose owner is not in the
// restored data. Short-lived sign-in state is left out of the dump entirely
// (signInTables).
type credentialTable struct {
	name string
	// key is the primary key column.
	key string
	// same are the columns that identify one credential. A restored row
	// matching a live row on all of them is that credential, so it is
	// updated in place and whatever refers to it stays linked.
	same []string
	// credential selects the rows that are credentials, over alias t: for
	// invitations only the pending ones; accepted and revoked invitations
	// are the restored history.
	credential string
	// owned is true, over the live row r, when everything it belongs to
	// exists in the restored data.
	owned string
	// describe names a dropped row, over r, without any key material.
	describe string
}

// everyRow is a credentialTable.credential that selects every row.
const everyRow = "true"

// credentialTables are the long-lived credentials a full restore keeps
// from the live server.
var credentialTables = []credentialTable{
	{
		name: "api_keys", key: "id", same: []string{"id", "user_id", "key_hash", "key_prefix"}, credential: everyRow,
		owned:    `EXISTS (SELECT 1 FROM users u WHERE u.id = r.user_id)`,
		describe: `format('API key %s %L (account %s)', r.id, r.label, r.user_id)`,
	},
	{
		name: "invitations", key: "id", same: []string{"id", "token_hash"},
		credential: `t.accepted_at IS NULL AND t.revoked_at IS NULL`,
		owned: `(r.invited_by IS NULL OR EXISTS (SELECT 1 FROM users u WHERE u.id = r.invited_by))
			AND (r.access_group_id IS NULL OR EXISTS (SELECT 1 FROM access_groups g WHERE g.id = r.access_group_id))`,
		describe: `format('invitation %s', r.id)`,
	},
	{
		name: "invite_codes", key: "id", same: []string{"id", "code"}, credential: everyRow,
		owned:    `r.created_by IS NULL OR EXISTS (SELECT 1 FROM users u WHERE u.id = r.created_by)`,
		describe: `format('invite code %s %L', r.id, r.label)`,
	},
	{
		name: "autoscan_webhook_endpoints", key: "source_id", same: []string{"source_id", "secret_hash"}, credential: everyRow,
		owned:    `EXISTS (SELECT 1 FROM autoscan_sources s WHERE s.id = r.source_id)`,
		describe: `format('autoscan webhook of source %s', r.source_id)`,
	},
}

// carriedKinds is what the restore output calls credentialTables.
const carriedKinds = "API keys, pending invitations, invite codes, and autoscan webhook tokens"

// CarriedCredentials is what DatabaseLoader.CarryCredentials did.
type CarriedCredentials struct {
	Kept int
	// Dropped names the live credentials left out because their owner is
	// not in the restored data, without key material.
	Dropped []string
}

// carryCredentials replaces the restored database's credentials with the
// live server's (liveURL), or with none when liveURL is "", and prints
// what it kept and dropped.
func carryCredentials(ctx context.Context, loader DatabaseLoader, dbURL, liveURL string, out io.Writer) error {
	carried, err := loader.CarryCredentials(ctx, dbURL, liveURL)
	if err != nil {
		return fmt.Errorf("replacing the restored %s: %w", carriedKinds, err)
	}
	if liveURL == "" {
		_, _ = fmt.Fprintf(out, "Left out the backup's %s; create new ones after Silo starts.\n", carriedKinds)
		return nil
	}
	_, _ = fmt.Fprintf(out, "Kept %d of this server's %s in place of the backup's.\n", carried.Kept, carriedKinds)
	if len(carried.Dropped) > 0 {
		_, _ = fmt.Fprintf(out, "Dropped %d whose account, access group, or source is not in the backup: %s\n",
			len(carried.Dropped), strings.Join(carried.Dropped, ", "))
	}
	return nil
}

// CarryCredentials replaces the credentialTables rows of dbURL with the
// rows of liveURL, or deletes them when liveURL is "", in one transaction.
func (l PGLoader) CarryCredentials(ctx context.Context, dbURL, liveURL string) (CarriedCredentials, error) {
	live := make([]string, len(credentialTables))
	for i := range live {
		live[i] = "[]"
	}
	if liveURL != "" {
		if err := readLiveCredentials(ctx, liveURL, live); err != nil {
			return CarriedCredentials{}, fmt.Errorf("reading the live server's credentials: %w", err)
		}
	}
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return CarriedCredentials{}, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	var carried CarriedCredentials
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		for i, table := range credentialTables {
			if err := table.carry(ctx, tx, live[i], &carried); err != nil {
				return fmt.Errorf("%s: %w", table.name, err)
			}
		}
		return nil
	})
	return carried, err
}

// readLiveCredentials reads each credential table of liveURL as one JSON
// array, in one snapshot.
func readLiveCredentials(ctx context.Context, liveURL string, into []string) error {
	conn, err := pgx.Connect(ctx, liveURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	return pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		for i, table := range credentialTables {
			sql := fmt.Sprintf(`SELECT coalesce(json_agg(t), '[]')::text FROM %s t WHERE %s`, table.name, table.credential)
			if err := tx.QueryRow(ctx, sql).Scan(&into[i]); err != nil {
				return fmt.Errorf("%s: %w", table.name, err)
			}
		}
		return nil
	})
}

// carry runs in the restored database: it deletes the restored credentials
// that are not the same as a carried live one, upserts the live ones whose
// owner exists, and moves an identity sequence past the ids it wrote. Only
// the columns the restored schema has are written, so a backup taken
// before a column was added still restores.
func (c credentialTable) carry(ctx context.Context, tx pgx.Tx, live string, carried *CarriedCredentials) error {
	rows := fmt.Sprintf(`json_populate_recordset(NULL::%s, $1::json) r`, c.name)
	dropped, err := collectStrings(ctx, tx, fmt.Sprintf(`SELECT %s FROM %s WHERE NOT (%s)`, c.describe, rows, c.owned), live)
	if err != nil {
		return err
	}
	carried.Dropped = append(carried.Dropped, dropped...)
	columns, err := collectStrings(ctx, tx, `
		SELECT attname::text FROM pg_attribute
		WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped AND attgenerated = ''
		ORDER BY attnum`, c.name)
	if err != nil {
		return err
	}
	same := slices.DeleteFunc(slices.Clone(c.same), func(col string) bool { return !slices.Contains(columns, col) })
	if _, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s t WHERE %s AND NOT EXISTS (
		SELECT 1 FROM %s WHERE (%s) AND (%s) = (%s))`,
		c.name, c.credential, rows, c.owned, prefixed("r.", same), prefixed("t.", same)), live); err != nil {
		return err
	}
	var set []string
	for _, col := range columns {
		if col != c.key {
			set = append(set, fmt.Sprintf("%s = EXCLUDED.%s", col, col))
		}
	}
	tag, err := tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE
		SELECT %s FROM %s WHERE %s
		ON CONFLICT (%s) DO UPDATE SET %s`,
		c.name, strings.Join(columns, ", "), prefixed("r.", columns), rows, c.owned, c.key, strings.Join(set, ", ")), live)
	if err != nil {
		return err
	}
	carried.Kept += int(tag.RowsAffected())
	// An identity sequence restored from the backup can be behind the live
	// ids just written; the next credential must not collide with them.
	var seq *string
	if err := tx.QueryRow(ctx, `SELECT pg_get_serial_sequence($1, $2)`, c.name, c.key).Scan(&seq); err != nil || seq == nil {
		return err
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`SELECT setval($1::regclass, GREATEST(
		coalesce(pg_sequence_last_value($1::regclass), 0), (SELECT coalesce(max(%s), 0) FROM %s), 1))`, c.key, c.name), *seq)
	return err
}

func prefixed(prefix string, columns []string) string {
	out := make([]string, len(columns))
	for i, col := range columns {
		out[i] = prefix + col
	}
	return strings.Join(out, ", ")
}
