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
	// leftOut tables hold short-lived secrets (sessions, sign-in flows,
	// reset and verification tokens): the dump leaves their rows out, so a
	// restore brings none back and every client signs in again.
	leftOut secretHandling = iota + 1
	// carried tables hold long-lived credentials that clients and other
	// services present to Silo. A full restore does not bring back the
	// backup's rows, since a credential revoked after the backup would work
	// again and one created since would stop working: it keeps the live
	// server's rows as they are right before the swap, less those whose
	// owner is not in the restored data. A separate restore keeps none.
	carried
	// restored tables are restored with the rest of the data: what looks
	// like a secret admits no one to this server, or belongs to the record
	// it is restored with (why says which).
	restored
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

// SQL conditions over the live row r, shared by several carried tables.
const (
	userExists    = `EXISTS (SELECT 1 FROM users u WHERE u.id = r.user_id)`
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
	{name: "auth_sessions", handling: leftOut, why: "web and native sign-ins and their refresh tokens"},
	{name: "device_login_requests", handling: leftOut, why: "device-code sign-ins, which name auth_sessions"},
	{name: "jellycompat_sessions", handling: leftOut, why: "Jellyfin-protocol access tokens"},
	{name: "jellycompat_device_profiles", handling: leftOut, why: "keyed by Jellyfin-protocol access tokens"},
	{name: "jellycompat_playback_sessions", handling: leftOut, why: "Jellyfin-protocol playback sessions"},
	{name: "abs_sessions", handling: leftOut, why: "Audiobookshelf-protocol sessions"},
	{name: "oauth_sessions", handling: leftOut, why: "OIDC sign-ins in progress"},
	{name: "oauth_completions", handling: leftOut, why: "OIDC sign-ins waiting to be redeemed"},
	{name: "oauth_native_starts", handling: leftOut, why: "native-app OIDC sign-ins in progress"},
	{name: "oauth_link_tickets", handling: leftOut, why: "account-link tickets"},
	{name: "oauth_pending_links", handling: leftOut, why: "account links waiting to be confirmed"},
	{name: "password_reset_tokens", handling: leftOut, why: "a token used after the backup would work again"},
	{name: "notification_email_verifications", handling: leftOut, why: "email-address verification tokens"},
	{name: "notification_discord_link_state", handling: leftOut, why: "Discord link flows in progress"},
	{name: "watch_provider_auth_sessions", handling: leftOut, why: "watch-provider device-code sign-ins in progress"},
	{name: "history_import_plex_sessions", handling: leftOut, why: "Plex sign-ins of a history import in progress"},
	{name: "history_import_connect_sessions", handling: leftOut, why: "Jellyfin Connect sign-ins of a history import in progress"},
	{name: "watch_together_rooms", handling: leftOut, why: watchTogether},
	{name: "watch_together_suggestions", handling: leftOut, why: watchTogether},
	{name: "watch_together_votes", handling: leftOut, why: watchTogether},
	{name: "backup_status", handling: leftOut, why: "describes the backup being taken, which would read as a stale run after a restore"},

	{name: "api_keys", handling: carried, why: "API keys", carry: &carrySpec{
		key: "id", same: []string{"id", columnUserID, "key_hash", "key_prefix"}, credential: everyRow, owned: userExists,
		describe: `format('API key %s %L (account %s)', r.id, r.label, r.user_id)`,
	}},
	{name: "invitations", handling: carried, why: "pending invitations", carry: &carrySpec{
		key: "id", same: []string{"id", "token_hash"}, credential: `t.accepted_at IS NULL AND t.revoked_at IS NULL`,
		owned: `(r.invited_by IS NULL OR EXISTS (SELECT 1 FROM users u WHERE u.id = r.invited_by))
			AND (r.access_group_id IS NULL OR EXISTS (SELECT 1 FROM access_groups g WHERE g.id = r.access_group_id))`,
		describe: `format('invitation %s', r.id)`,
	}},
	{name: "invite_codes", handling: carried, why: "invite codes", carry: &carrySpec{
		key: "id", same: []string{"id", "code"}, credential: everyRow,
		owned:    `r.created_by IS NULL OR EXISTS (SELECT 1 FROM users u WHERE u.id = r.created_by)`,
		describe: `format('invite code %s %L', r.id, r.label)`,
	}},
	{name: "autoscan_webhook_endpoints", handling: carried, why: "autoscan webhook tokens", carry: &carrySpec{
		key: "source_id", same: []string{"source_id", "secret_hash"}, credential: everyRow,
		owned:    `EXISTS (SELECT 1 FROM autoscan_sources s WHERE s.id = r.source_id)`,
		describe: `format('autoscan webhook of source %s', r.source_id)`,
	}},
	{name: "abs_rss_feeds", handling: carried, why: "audiobook RSS feed links", carry: &carrySpec{
		key: "id", same: []string{"id", columnUserID, "slug"}, credential: everyRow,
		owned: userExists + `
			AND EXISTS (SELECT 1 FROM media_items m WHERE m.content_id = r.library_item_id)
			AND (r.profile_id IS NULL OR EXISTS (SELECT 1 FROM user_profiles p WHERE p.id = r.profile_id::text))`,
		describe: `format('RSS feed %s (account %s)', r.id, r.user_id)`,
	}},
	{name: "webhook_sync_connections", handling: carried, why: "Plex and Jellyfin webhook sync secrets", carry: &carrySpec{
		key: "id", same: []string{"id", columnUserID, "webhook_secret"}, credential: everyRow,
		owned: userExists + `
			AND (r.default_profile_id = '' OR EXISTS (SELECT 1 FROM user_profiles p WHERE p.id = r.default_profile_id))`,
		describe: `format('webhook sync connection %s %L (account %s)', r.id, r.server_name, r.user_id)`,
	}},
	{name: "webhook_sync_profile_mappings", handling: carried, why: "the profile mappings of those connections", carry: &carrySpec{
		key: "id", same: []string{"id", "connection_id", "external_user_id"}, credential: everyRow,
		owned: `EXISTS (SELECT 1 FROM webhook_sync_connections c WHERE c.id = r.connection_id)
			AND (r.silo_profile_id IS NULL OR EXISTS (SELECT 1 FROM user_profiles p WHERE p.id = r.silo_profile_id))`,
		describe: `format('webhook sync mapping %s of connection %s', r.id, r.connection_id)`,
	}},

	{name: "users", handling: restored, why: "account passwords, restored with the accounts they sign in to"},
	{name: tableUserProfiles, handling: restored, why: "profile PINs, restored with their profiles"},
	{name: "notification_email_prefs", handling: restored, why: "an unsubscribe link and an address check, which only change the owner's email settings"},
	{name: "apple_push_installations", handling: restored, why: "a device's key for its own push registration, which admits nothing else"},
	{name: "android_push_installations", handling: restored, why: "a device's key for its own push registration, which admits nothing else"},
	{name: "marker_edit_audit", handling: restored, why: "names the API key an edit came from"},
	{name: "push_devices", handling: restored, why: outboundOnly},
	{name: "watch_provider_connections", handling: restored, why: outboundOnly},
	{name: "history_import_sources", handling: restored, why: outboundOnly},
	{name: "subtitle_provider_config", handling: restored, why: outboundOnly},
	{name: "notification_server_channels", handling: restored, why: outboundOnly},
	{name: "notification_webhooks", handling: restored, why: outboundOnly},
	{name: "autoscan_connections", handling: restored, why: outboundOnly},
	{name: "request_integrations", handling: restored, why: outboundOnly},
	{name: tableLibraryCollections, handling: restored, why: urlSlug},
	{name: "library_collection_groups", handling: restored, why: urlSlug},
	{name: "user_collection_groups", handling: restored, why: urlSlug},
	{name: "audiobook_enrichment_state", handling: restored, why: workerLease},
	{name: "ebook_enrichment_state", handling: restored, why: workerLease},
	{name: "embedded_subtitle_track_claims", handling: restored, why: workerLease},
	{name: "marker_contributions", handling: restored, why: workerLease},
	{name: "marker_fetch_state", handling: restored, why: workerLease},
	{name: "movie_match_queue", handling: restored, why: workerLease},
	{name: "series_root_match_queue", handling: restored, why: workerLease},
	{name: "idgen_machine_leases", handling: restored, why: workerLease},
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

// leftOutTables names the leftOut tables, whose rows the dump leaves out.
func leftOutTables() []string {
	var names []string
	for _, t := range secretTablesHandled(leftOut) {
		names = append(names, t.name)
	}
	return names
}

// carriedKinds is what the restore output calls the carried tables.
const carriedKinds = "API keys, pending invitations, invite codes, autoscan webhook tokens, audiobook RSS feed links, " +
	"and Plex and Jellyfin webhook sync secrets"

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

// CarryCredentials replaces the carried secretTables rows of dbURL with
// the rows of liveURL, or deletes them when liveURL is "", in one
// transaction.
func (l PGLoader) CarryCredentials(ctx context.Context, dbURL, liveURL string) (CarriedCredentials, error) {
	tables := secretTablesHandled(carried)
	live := make([]string, len(tables))
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
	var result CarriedCredentials
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
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
// array, in one snapshot.
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
		return nil
	})
}

// carry runs in the restored database: it deletes the restored credentials
// that are not the same as a carried live one, upserts the live ones whose
// owner exists, and moves an identity sequence past the ids it wrote. Only
// the columns the restored schema has are written, so a backup taken
// before a column was added still restores.
func (t secretTable) carryInto(ctx context.Context, tx pgx.Tx, live string, carried *CarriedCredentials) error {
	c := t.carry
	rows := fmt.Sprintf(`json_populate_recordset(NULL::%s, $1::json) r`, t.name)
	dropped, err := collectStrings(ctx, tx, fmt.Sprintf(`SELECT %s FROM %s WHERE NOT (%s)`, c.describe, rows, c.owned), live)
	if err != nil {
		return err
	}
	carried.Dropped = append(carried.Dropped, dropped...)
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
	carried.Kept += int(tag.RowsAffected())
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
