package backup

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// secretHandling is what a backup and a restore do with a table holding a
// bearer secret or a public capability.
type secretHandling int

const (
	// secretLeftOut tables hold short-lived secrets (sessions, sign-in flows,
	// reset and verification tokens): the dump leaves their rows out, so a
	// restore brings none back and every client signs in again.
	secretLeftOut secretHandling = iota + 1
	// secretCarried tables hold long-lived credentials that clients and other
	// services present to Silo. A full restore does not bring back the
	// backup's rows, since a credential revoked after the backup would work
	// again and one created since would stop working: it keeps the live
	// server's rows as they are right before the swap, less those whose
	// owner is not in the restored data. A separate restore keeps none.
	secretCarried
	// secretRestored tables are restored with the rest of the data: what looks
	// like a secret admits no one to this server, or belongs to the record
	// it is restored with (why says which).
	secretRestored
)

// secretTable is one table of secretTables.
type secretTable struct {
	name     string
	handling secretHandling
	why      string
	// carry says how a carried table's live rows replace the restored ones.
	carry *carrySpec
}

// carrySpec is how carryCredentials replaces a carried table's rows.
type carrySpec struct {
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

// everyRow is a carrySpec.credential that selects every row.
const everyRow = "true"

// columnUserID is the owner column of several carried tables.
const columnUserID = "user_id"

// ownerNotElevated is the SQL condition, over the live row r, that the
// account in column exists in the restored data with no more authority than
// it has on the live server (liveAuthority): a higher role (the Owner over
// admin over user), enabled where it is disabled now, break-glass access,
// or a permission it lacks now. A live credential of an account demoted
// since the backup would otherwise carry the snapshot's authority; changing
// an account's role deletes its keys for the same reason.
func ownerNotElevated(column string) string {
	return `EXISTS (SELECT 1 FROM users u JOIN live_authority l ON l.id = u.id
		WHERE u.id = r.` + column + `
		  AND (CASE WHEN u.is_owner THEN 2 WHEN u.role = 'admin' THEN 1 ELSE 0 END) <= l.rank
		  AND (NOT u.enabled OR l.enabled) AND (NOT u.break_glass OR l.break_glass)
		  AND u.permissions <@ l.permissions)`
}

// liveAuthority reads, on the live server, what ownerNotElevated compares.
const liveAuthority = `SELECT coalesce(json_agg(json_build_object('id', id,
	'rank', CASE WHEN is_owner THEN 2 WHEN role = 'admin' THEN 1 ELSE 0 END,
	'enabled', enabled, 'break_glass', break_glass, 'permissions', permissions)), '[]')::text FROM users`

// SQL conditions over the live row r, shared by several carried tables.
const (
	outboundOnly  = "outbound: what Silo presents to another service, not a credential for Silo"
	workerLease   = "a worker's lease or claim on a job, not a credential"
	urlSlug       = "a URL name, not a secret"
	watchTogether = "Watch Together rooms in progress and their join codes"
)

// secretTables classifies every table holding a bearer secret or a public
// capability. Carried tables are replaced in this order, so a table follows
// the ones its owner condition reads. TestSecretTablesAreClassifiedDB scans
// the schema for secret-like columns and fails on a table missing here.
var secretTables = []secretTable{
	{name: "auth_sessions", handling: secretLeftOut, why: "web and native sign-ins and their refresh tokens"},
	{name: "device_login_requests", handling: secretLeftOut, why: "device-code sign-ins, which name auth_sessions"},
	{name: "jellycompat_sessions", handling: secretLeftOut, why: "Jellyfin-protocol access tokens"},
	{name: "jellycompat_device_profiles", handling: secretLeftOut, why: "keyed by Jellyfin-protocol access tokens"},
	{name: "jellycompat_playback_sessions", handling: secretLeftOut, why: "Jellyfin-protocol playback sessions"},
	{name: "abs_sessions", handling: secretLeftOut, why: "Audiobookshelf-protocol sessions"},
	{name: "oauth_sessions", handling: secretLeftOut, why: "OIDC sign-ins in progress"},
	{name: "oauth_completions", handling: secretLeftOut, why: "OIDC sign-ins waiting to be redeemed"},
	{name: "oauth_native_starts", handling: secretLeftOut, why: "native-app OIDC sign-ins in progress"},
	{name: "oauth_link_tickets", handling: secretLeftOut, why: "account-link tickets"},
	{name: "oauth_pending_links", handling: secretLeftOut, why: "account links waiting to be confirmed"},
	{name: "password_reset_tokens", handling: secretLeftOut, why: "a token used after the backup would work again"},
	{name: "notification_email_verifications", handling: secretLeftOut, why: "email-address verification tokens"},
	{name: "notification_discord_link_state", handling: secretLeftOut, why: "Discord link flows in progress"},
	{name: "watch_provider_auth_sessions", handling: secretLeftOut, why: "watch-provider device-code sign-ins in progress"},
	{name: "history_import_plex_sessions", handling: secretLeftOut, why: "Plex sign-ins of a history import in progress"},
	{name: "history_import_connect_sessions", handling: secretLeftOut, why: "Jellyfin Connect sign-ins of a history import in progress"},
	{name: "watch_together_rooms", handling: secretLeftOut, why: watchTogether},
	{name: "watch_together_suggestions", handling: secretLeftOut, why: watchTogether},
	{name: "watch_together_votes", handling: secretLeftOut, why: watchTogether},
	{name: "backup_status", handling: secretLeftOut, why: "describes the backup being taken, which would read as a stale run after a restore"},

	{name: "api_keys", handling: secretCarried, why: "API keys", carry: &carrySpec{
		key: "id", same: []string{"id", columnUserID, "key_hash", "key_prefix"}, credential: everyRow, owned: ownerNotElevated(columnUserID),
		describe: `format('API key %s %L (account %s)', r.id, r.label, r.user_id)`,
	}},
	{name: "invitations", handling: secretCarried, why: "pending invitations", carry: &carrySpec{
		key: "id", same: []string{"id", "token_hash"}, credential: `t.accepted_at IS NULL AND t.revoked_at IS NULL`,
		owned: `(r.invited_by IS NULL OR ` + ownerNotElevated("invited_by") + `)
			AND (r.access_group_id IS NULL OR EXISTS (SELECT 1 FROM access_groups g WHERE g.id = r.access_group_id))`,
		describe: `format('invitation %s', r.id)`,
	}},
	{name: "invite_codes", handling: secretCarried, why: "invite codes", carry: &carrySpec{
		key: "id", same: []string{"id", "code"}, credential: everyRow,
		owned:    `r.created_by IS NULL OR ` + ownerNotElevated("created_by"),
		describe: `format('invite code %s %L', r.id, r.label)`,
	}},
	{name: "autoscan_webhook_endpoints", handling: secretCarried, why: "autoscan webhook tokens", carry: &carrySpec{
		key: "source_id", same: []string{"source_id", "secret_hash"}, credential: everyRow,
		owned:    `EXISTS (SELECT 1 FROM autoscan_sources s WHERE s.id = r.source_id)`,
		describe: `format('autoscan webhook of source %s', r.source_id)`,
	}},
	{name: "abs_rss_feeds", handling: secretCarried, why: "audiobook RSS feed links", carry: &carrySpec{
		key: "id", same: []string{"id", columnUserID, "slug"}, credential: everyRow,
		owned: ownerNotElevated(columnUserID) + `
			AND EXISTS (SELECT 1 FROM media_items m WHERE m.content_id = r.library_item_id)
			AND (r.profile_id IS NULL OR EXISTS (SELECT 1 FROM user_profiles p WHERE p.id = r.profile_id::text))`,
		describe: `format('RSS feed %s (account %s)', r.id, r.user_id)`,
	}},
	{name: "webhook_sync_connections", handling: secretCarried, why: "Plex and Jellyfin webhook sync secrets", carry: &carrySpec{
		key: "id", same: []string{"id", columnUserID, "webhook_secret"}, credential: everyRow,
		owned: ownerNotElevated(columnUserID) + `
			AND (r.default_profile_id = '' OR EXISTS (SELECT 1 FROM user_profiles p WHERE p.id = r.default_profile_id))`,
		describe: `format('webhook sync connection %s %L (account %s)', r.id, r.server_name, r.user_id)`,
	}},
	{name: "webhook_sync_profile_mappings", handling: secretCarried, why: "the profile mappings of those connections", carry: &carrySpec{
		key: "id", same: []string{"id", "connection_id", "external_user_id"}, credential: everyRow,
		owned: `EXISTS (SELECT 1 FROM webhook_sync_connections c WHERE c.id = r.connection_id)
			AND (r.silo_profile_id IS NULL OR EXISTS (SELECT 1 FROM user_profiles p WHERE p.id = r.silo_profile_id))`,
		describe: `format('webhook sync mapping %s of connection %s', r.id, r.connection_id)`,
	}},

	{name: "users", handling: secretRestored, why: "account passwords, restored with the accounts they sign in to"},
	{name: tableUserProfiles, handling: secretRestored, why: "profile PINs, restored with their profiles"},
	{name: "notification_email_prefs", handling: secretRestored, why: "an unsubscribe link and an address check, which only change the owner's email settings"},
	{name: "apple_push_installations", handling: secretRestored, why: "a device's key for its own push registration, which admits nothing else"},
	{name: "android_push_installations", handling: secretRestored, why: "a device's key for its own push registration, which admits nothing else"},
	{name: "marker_edit_audit", handling: secretRestored, why: "names the API key an edit came from"},
	{name: "push_devices", handling: secretRestored, why: outboundOnly},
	{name: "watch_provider_connections", handling: secretRestored, why: outboundOnly},
	{name: "history_import_sources", handling: secretRestored, why: outboundOnly},
	{name: "subtitle_provider_config", handling: secretRestored, why: outboundOnly},
	{name: "notification_server_channels", handling: secretRestored, why: outboundOnly},
	{name: "notification_webhooks", handling: secretRestored, why: outboundOnly},
	{name: "autoscan_connections", handling: secretRestored, why: outboundOnly},
	{name: "request_integrations", handling: secretRestored, why: outboundOnly},
	{name: tableLibraryCollections, handling: secretRestored, why: urlSlug},
	{name: "library_collection_groups", handling: secretRestored, why: urlSlug},
	{name: "user_collection_groups", handling: secretRestored, why: urlSlug},
	{name: "audiobook_enrichment_state", handling: secretRestored, why: workerLease},
	{name: "ebook_enrichment_state", handling: secretRestored, why: workerLease},
	{name: "embedded_subtitle_track_claims", handling: secretRestored, why: workerLease},
	{name: "marker_contributions", handling: secretRestored, why: workerLease},
	{name: "marker_fetch_state", handling: secretRestored, why: workerLease},
	{name: "movie_match_queue", handling: secretRestored, why: workerLease},
	{name: "series_root_match_queue", handling: secretRestored, why: workerLease},
	{name: "idgen_machine_leases", handling: secretRestored, why: workerLease},
}

// secretTablesHandled lists the secretTables handled one way, in order.
func secretTablesHandled(h secretHandling) []secretTable {
	var out []secretTable
	for _, t := range secretTables {
		if t.handling == h {
			out = append(out, t)
		}
	}
	return out
}

// leftOutTables names the secretLeftOut tables, whose rows the dump leaves out.
func leftOutTables() []string {
	var names []string
	for _, t := range secretTablesHandled(secretLeftOut) {
		names = append(names, t.name)
	}
	return names
}

// carriedKinds is what the restore output calls the carried tables.
const carriedKinds = "API keys, pending invitations, invite codes, autoscan webhook tokens, audiobook RSS feed links, " +
	"and Plex and Jellyfin webhook sync secrets"

// CarriedCredentials is what DatabaseLoader.CarryCredentials did.
type CarriedCredentials struct {
	// Kept counts the live rows kept, by table.
	Kept map[string]int
	// Dropped names the live credentials left out because their owner is
	// not in the restored data or has more authority there, without key
	// material.
	Dropped []string
}

// carryCredentials replaces the restored database's credentials with the
// live server's (liveURL), or with none when liveURL is "", and prints
// what it kept and dropped.
func carryCredentials(ctx context.Context, loader DatabaseLoader, dbURL, liveURL string, out io.Writer) error {
	carriedRows, err := loader.CarryCredentials(ctx, dbURL, liveURL)
	if err != nil {
		return fmt.Errorf("replacing the restored %s: %w", carriedKinds, err)
	}
	if liveURL == "" {
		_, _ = fmt.Fprintf(out, "Left out the backup's %s; create new ones after Silo starts.\n", carriedKinds)
		return nil
	}
	var kept []string
	for _, t := range secretTablesHandled(secretCarried) {
		if n := carriedRows.Kept[t.name]; n > 0 {
			kept = append(kept, fmt.Sprintf("%s (%d)", t.why, n))
		}
	}
	if len(kept) == 0 {
		kept = append(kept, "none")
	}
	_, _ = fmt.Fprintf(out, "Kept this server's %s in place of the backup's: %s.\n", carriedKinds, strings.Join(kept, ", "))
	if len(carriedRows.Dropped) > 0 {
		_, _ = fmt.Fprintf(out, "Dropped %d whose owner is not in the backup or has more authority there than here: %s\n",
			len(carriedRows.Dropped), strings.Join(carriedRows.Dropped, ", "))
	}
	return nil
}

// CarryCredentials replaces the carried secretTables rows of dbURL with
// the rows of liveURL, or deletes them when liveURL is "", in one
// transaction.
func (l PGLoader) CarryCredentials(ctx context.Context, dbURL, liveURL string) (CarriedCredentials, error) {
	tables := secretTablesHandled(secretCarried)
	// The live rows of each table, then the live accounts' authority.
	live := make([]string, len(tables)+1)
	for i := range live {
		live[i] = "[]"
	}
	if liveURL != "" {
		if err := readLiveCredentials(ctx, liveURL, tables, live); err != nil {
			return CarriedCredentials{}, fmt.Errorf("reading the live server's credentials: %w", err)
		}
	}
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return CarriedCredentials{}, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	result := CarriedCredentials{Kept: map[string]int{}}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			CREATE TEMP TABLE live_authority ON COMMIT DROP AS
			SELECT * FROM json_to_recordset($1::json) AS a(id bigint, rank int, enabled boolean, break_glass boolean, permissions text[])`,
			live[len(tables)]); err != nil {
			return fmt.Errorf("reading the live accounts' authority: %w", err)
		}
		for i, table := range tables {
			if err := table.carryInto(ctx, tx, live[i], &result); err != nil {
				return fmt.Errorf("%s: %w", table.name, err)
			}
		}
		return nil
	})
	return result, err
}

// readLiveCredentials reads each credential table of liveURL as one JSON
// array, and last the accounts' authority (liveAuthority), in one snapshot.
func readLiveCredentials(ctx context.Context, liveURL string, tables []secretTable, into []string) error {
	conn, err := pgx.Connect(ctx, liveURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	return pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		for i, table := range tables {
			sql := fmt.Sprintf(`SELECT coalesce(json_agg(t), '[]')::text FROM %s t WHERE %s`, table.name, table.carry.credential)
			if err := tx.QueryRow(ctx, sql).Scan(&into[i]); err != nil {
				return fmt.Errorf("%s: %w", table.name, err)
			}
		}
		return tx.QueryRow(ctx, liveAuthority).Scan(&into[len(tables)])
	})
}

// carry runs in the restored database: it deletes the restored credentials
// that are not the same as a carried live one, upserts the live ones whose
// owner exists, and moves an identity sequence past the ids it wrote. Only
// the columns the restored schema has are written, so a backup taken
// before a column was added still restores.
func (t secretTable) carryInto(ctx context.Context, tx pgx.Tx, live string, result *CarriedCredentials) error {
	c := t.carry
	rows := fmt.Sprintf(`json_populate_recordset(NULL::%s, $1::json) r`, t.name)
	dropped, err := collectStrings(ctx, tx, fmt.Sprintf(`SELECT %s FROM %s WHERE NOT (%s)`, c.describe, rows, c.owned), live)
	if err != nil {
		return err
	}
	result.Dropped = append(result.Dropped, dropped...)
	columns, err := collectStrings(ctx, tx, `
		SELECT attname::text FROM pg_attribute
		WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped AND attgenerated = ''
		ORDER BY attnum`, t.name)
	if err != nil {
		return err
	}
	same := slices.DeleteFunc(slices.Clone(c.same), func(col string) bool { return !slices.Contains(columns, col) })
	if _, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s t WHERE %s AND NOT EXISTS (
		SELECT 1 FROM %s WHERE (%s) AND (%s) = (%s))`,
		t.name, c.credential, rows, c.owned, prefixed("r.", same), prefixed("t.", same)), live); err != nil {
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
		t.name, strings.Join(columns, ", "), prefixed("r.", columns), rows, c.owned, c.key, strings.Join(set, ", ")), live)
	if err != nil {
		return err
	}
	result.Kept[t.name] += int(tag.RowsAffected())
	// An identity sequence restored from the backup can be behind the live
	// ids just written; the next credential must not collide with them.
	var seq *string
	if err := tx.QueryRow(ctx, `SELECT pg_get_serial_sequence($1, $2)`, t.name, c.key).Scan(&seq); err != nil || seq == nil {
		return err
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`SELECT setval($1::regclass, GREATEST(
		coalesce(pg_sequence_last_value($1::regclass), 0), (SELECT coalesce(max(%s), 0) FROM %s), 1))`, c.key, t.name), *seq)
	return err
}

func prefixed(prefix string, columns []string) string {
	out := make([]string, len(columns))
	for i, col := range columns {
		out[i] = prefix + col
	}
	return strings.Join(out, ", ")
}
