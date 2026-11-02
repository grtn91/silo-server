package config

import "testing"

// TestAccessSettingWider: a backup restore writes an access setting only
// when its value grants no more than the live one.
func TestAccessSettingWider(t *testing.T) {
	for _, tc := range []struct {
		key, restored, live string
		wider               bool
	}{
		{AccessUnratedContentSettingKey, "allow", "hide", true},
		{AccessUnratedContentSettingKey, "allow", "", true}, // unset hides
		{AccessUnratedContentSettingKey, "hide", "allow", false},
		{AccessUnratedContentSettingKey, "allow", "allow", false},
		{AuthProviderRecheckOutagePolicySettingKey, AuthRecheckFailOpen, AuthRecheckFailClosed, true},
		{AuthProviderRecheckOutagePolicySettingKey, "", AuthRecheckFailClosed, true}, // the default fails open
		{AuthProviderRecheckOutagePolicySettingKey, AuthRecheckFailClosed, AuthRecheckFailOpen, false},
		{"jellyfin_compat.enabled", "true", "false", true},
		{"jellyfin_compat.enabled", "false", "true", false},
		{"audiobookshelf_compat.enabled", "", "false", true},
		{AuthRefreshTokenExpirySettingKey, "90d", "30d", true},
		{AuthRefreshTokenExpirySettingKey, "7d", "30d", false},
		{"auth.access_token_expiry", "1h", "", false},
		{"jellyfin_compat.session_ttl", "87601h", "", true},
		{AuthRefreshTokenExpirySettingKey, "forever", "30d", true}, // unreadable keeps the live value
	} {
		access, wider := AccessSettingWider(tc.key, tc.restored, tc.live)
		if !access || wider != tc.wider {
			t.Errorf("AccessSettingWider(%s, %q, %q) = %v, %v; want access, wider %v", tc.key, tc.restored, tc.live, access, wider, tc.wider)
		}
	}
	if access, _ := AccessSettingWider("server.log_level", "debug", "info"); access {
		t.Error("server.log_level is not an access setting")
	}
	for _, key := range AccessSettingKeys() {
		if _, ok := adminSettingDefaults[key]; !ok {
			t.Errorf("access setting %s has no admin default", key)
		}
	}
}
