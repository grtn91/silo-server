package backup

import (
	"regexp"
	"testing"

	"github.com/Silo-Server/silo-server/internal/branding"
	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/config"
)

// TestEverySettingIsClassified: the restore table is an allowlist, so a new
// admin setting is never offered by accident, and never silently left out:
// every key with an admin default, every sensitive key, and every branding
// asset key must have a class and a known page.
func TestEverySettingIsClassified(t *testing.T) {
	keys := config.AdminSettingDefaultKeys()
	for key := range catalog.SensitiveSettingKeys {
		keys = append(keys, key)
	}
	keys = append(keys, branding.AssetSettingKeys()...)
	for _, key := range keys {
		rule, ok := classifySetting(key)
		if !ok {
			t.Errorf("setting %q is not classified in settingRules", key)
			continue
		}
		if _, ok := settingsPageByID(rule.page); !ok {
			t.Errorf("setting %q names unknown page %q", key, rule.page)
		}
	}
}

// TestServerSpecificSettingsAreNeverOffered pins the spec's list of settings
// that describe this server rather than how it behaves.
func TestServerSpecificSettingsAreNeverOffered(t *testing.T) {
	for _, key := range []string{
		"server.identity_id", "server.public_url", "artwork.local_path", "s3.private_secret_key",
		"catalog.search.meilisearch.api_key", "userdb.backend", "notifications.push_relay_api_key", "auth.jwt_secret",
		"backup.keep", "storage.transition.target", "redis.url", "branding.mark_ref",
		"recommendations.embedding_lock", "recommendations.policy_marked_generation",
	} {
		if _, offered := RestorableSetting(key); offered {
			t.Errorf("%q is offered for restore", key)
		}
	}
	for key, want := range map[string]SettingClass{
		"email.smtp_password": SettingExternalService, "branding.server_name": SettingPortable,
		"catalog.search.meilisearch.timeout_ms": SettingPortable,
	} {
		rule, offered := RestorableSetting(key)
		if !offered || rule.class != want {
			t.Errorf("%q: offered %v class %q, want %q", key, offered, rule.class, want)
		}
	}
}

// TestAccessSettingsAreComparedOnRestore: an access setting (accessSettings)
// a selective restore offers is compared with the live value; every other
// one is server-specific and never written. Every trust setting is an
// access setting, so a full restore keeps it as strict as live too.
func TestAccessSettingsAreComparedOnRestore(t *testing.T) {
	for _, key := range AccessSettingKeys() {
		rule, ok := classifySetting(key)
		if !ok {
			t.Errorf("access setting %s is not classified", key)
			continue
		}
		if _, offered := RestorableSetting(key); !offered && rule.class != SettingServerSpecific {
			t.Errorf("access setting %s is neither offered nor server-specific: %+v", key, rule)
		}
	}
	for _, key := range trustSettings {
		if access, _ := AccessSettingWider(key, "", ""); !access {
			t.Errorf("trust setting %s is not an access setting", key)
		}
	}
}

// TestTrustSettingsAreServerSpecific: every network-security and sign-in
// trust toggle is server-specific, never restored, and every admin setting
// named like one (private destinations, trusted proxies, origins, TLS
// verification, sign-up and sign-in switches) is in trustSettings, so a
// new one cannot be restored from a backup without a decision.
func TestTrustSettingsAreServerSpecific(t *testing.T) {
	trusted := map[string]bool{}
	for _, key := range trustSettings {
		trusted[key] = true
		if rule, ok := classifySetting(key); !ok || rule.class != SettingServerSpecific {
			t.Errorf("%s is %+v, want server-specific", key, rule)
		}
	}
	looksLikeTrust := regexp.MustCompile(`allow_private|trusted|allowed_origins|cors|insecure|skip_verify|tls_verify|signup\.enabled|local_password_login|email_auto_match|self_service`)
	for _, key := range config.AdminSettingDefaultKeys() {
		if looksLikeTrust.MatchString(key) && !trusted[key] {
			t.Errorf("%s looks like a trust setting; add it to trustSettings and classify it server-specific", key)
		}
	}
}
