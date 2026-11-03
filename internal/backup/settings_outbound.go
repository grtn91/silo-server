package backup

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// settingOff is a switch setting turned off.
const settingOff = "false"

// outboundBundle is a set of settings that together say where this server
// connects outside and how it signs in there: an address with the secrets
// sent to it (settingRoutes), or a credential for a fixed service.
type outboundBundle struct {
	// keys are every setting of the bundle.
	keys []string
	// secrets are the ones cleared where the live server has no bundle.
	secrets []string
	// enabled is the switch turned off then, or "".
	enabled string
}

// outboundBundles are the settings a full restore never takes from the
// backup on their own (CarryOutboundSettings): the endpoint and secret
// routes, and the server's credentials for outside services.
var outboundBundles = func() []outboundBundle {
	var out []outboundBundle
	for _, r := range settingRoutes {
		out = append(out, outboundBundle{keys: r.keys(), secrets: r.secrets, enabled: r.enabled})
	}
	whole := func(keys ...string) outboundBundle { return outboundBundle{keys: keys, secrets: keys} }
	out = append(out,
		whole("ai.providers"),
		whole("ai.chatgpt.credentials"),
		outboundBundle{keys: []string{"notifications.push_relay_url", "notifications.push_relay_api_key", "notifications.push_relay_deployment_id",
			"notifications.push_relay_key_prefix", "notifications.push_relay_expires_at", "notifications.push_relay_reregistration_required"},
			secrets: []string{"notifications.push_relay_api_key"}},
		outboundBundle{keys: []string{"catalog.search.meilisearch.url", "catalog.search.meilisearch.api_key"},
			secrets: []string{"catalog.search.meilisearch.api_key"}},
		outboundBundle{keys: []string{"discord.client_id", "discord.client_secret", "discord.bot_token"},
			secrets: []string{"discord.client_secret", "discord.bot_token"}},
		whole("tmdb.api_key"), whole("mdblist.api_key"), whole("introdb.api_key"),
		whole("requests.radarr.api_key"), whole("requests.sonarr.api_key"),
		whole("watchsync.trakt.client_secret"), outboundBundle{keys: []string{"watchsync.simkl.client_id", "watchsync.simkl.client_secret"},
			secrets: []string{"watchsync.simkl.client_id", "watchsync.simkl.client_secret"}},
		whole("watchsync.healthy.client_secret"), whole("watchsync.slow.client_secret"),
	)
	return out
}()

// outboundKeys lists every setting of outboundBundles.
func outboundKeys() []string {
	var keys []string
	for _, b := range outboundBundles {
		keys = append(keys, b.keys...)
	}
	return keys
}

// CarryOutboundSettings gives the restored database (dbURL) the live
// server's (liveURL's) outbound settings, each bundle as a unit: a
// backup's address never reaches the live secrets, nor the backup's
// secrets a service again. A bundle the live server does not have, or
// every bundle when liveURL is "" (another deployment, or a separate
// restore), keeps the backup's other settings with its secrets cleared and
// its switch off. It returns the bundles it took from the live server and
// those it cleared, by their first key.
func (l PGLoader) CarryOutboundSettings(ctx context.Context, dbURL, liveURL string) (carried, cleared []string, err error) {
	live := map[string]string{}
	if liveURL != "" {
		if live, err = readSettingsAt(ctx, liveURL, outboundKeys()); err != nil {
			return nil, nil, fmt.Errorf("reading the live server's settings: %w", err)
		}
	}
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		restored, err := settingRows(ctx, tx, outboundKeys())
		if err != nil {
			return err
		}
		for _, b := range outboundBundles {
			if slices.ContainsFunc(b.keys, func(k string) bool { _, ok := live[k]; return ok }) {
				if err := b.takeLive(ctx, tx, live); err != nil {
					return err
				}
				carried = append(carried, b.keys[0])
				continue
			}
			if !slices.ContainsFunc(b.secrets, func(k string) bool { return restored[k] != "" }) {
				continue
			}
			if err := b.clear(ctx, tx); err != nil {
				return err
			}
			cleared = append(cleared, b.keys[0])
		}
		return nil
	})
	return carried, cleared, err
}

// takeLive replaces the bundle's settings in tx with the live ones.
func (b outboundBundle) takeLive(ctx context.Context, tx pgx.Tx, live map[string]string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM server_settings WHERE key = ANY($1)`, b.keys); err != nil {
		return err
	}
	for _, k := range b.keys {
		if v, ok := live[k]; ok {
			if _, err := tx.Exec(ctx, `INSERT INTO server_settings (key, value) VALUES ($1, $2)`, k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// clear deletes the bundle's secrets in tx and turns its switch off.
func (b outboundBundle) clear(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `DELETE FROM server_settings WHERE key = ANY($1)`, b.secrets); err != nil {
		return err
	}
	if b.enabled == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO server_settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, b.enabled, settingOff)
	return err
}

// carryOutboundSettings takes the outbound settings from the live server
// (liveURL, or none for "") and says what it cleared.
func carryOutboundSettings(ctx context.Context, loader DatabaseLoader, dbURL, liveURL string, out io.Writer) error {
	carried, cleared, err := loader.CarryOutboundSettings(ctx, dbURL, liveURL)
	if err != nil {
		return fmt.Errorf("keeping the live server's connections to outside services: %w", err)
	}
	if len(carried) > 0 {
		_, _ = fmt.Fprintf(out, "Kept this server's connections to outside services in place of the backup's: %s.\n", strings.Join(carried, ", "))
	}
	if len(cleared) > 0 {
		_, _ = fmt.Fprintf(out, "Cleared the backup's credentials for outside services this server does not have, and turned them off; enter them again to use them: %s.\n",
			strings.Join(cleared, ", "))
	}
	return nil
}
