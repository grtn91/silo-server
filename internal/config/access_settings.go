package config

import (
	"sort"
	"strconv"
	"strings"
)

// accessSettings are the server settings that decide who can reach this
// server and what a viewer sees: whether a title without a rating shows
// under a profile's rating ceiling, whether the Jellyfin and Audiobookshelf
// sign-in surfaces are on, how long sessions last, and whether an identity
// provider that cannot be reached still vouches for an account. Each maps a
// value to how much it grants (more is wider), or reports a value it cannot
// read.
//
// A backup restore writes one only when its value grants no more than the
// live one (AccessSettingWider). Sign-up, password sign-in, and the
// network-trust toggles are never restored at all.
var accessSettings = map[string]func(string) (int64, bool){
	AccessUnratedContentSettingKey: func(v string) (int64, bool) {
		// Anything but an explicit "allow" hides, as UnratedContentPolicy reads it.
		if strings.EqualFold(strings.TrimSpace(v), AccessUnratedContentAllow) {
			return 1, true
		}
		return 0, true
	},
	// A weaker transport sends the server's mail credentials where they
	// can be read.
	keySMTPSecurity: func(v string) (int64, bool) {
		switch v {
		case smtpSecurityNone:
			return 1, true
		case smtpSecurityStartTLS, smtpSecurityTLS:
			return 0, true
		}
		return 0, false
	},
	AuthProviderRecheckOutagePolicySettingKey: func(v string) (int64, bool) {
		switch v {
		case AuthRecheckFailOpen:
			return 1, true
		case AuthRecheckFailClosed:
			return 0, true
		}
		return 0, false
	},
	keyJellyfinEnabled:      grantsWhenTrue,
	keyJellyfinWebEnabled:   grantsWhenTrue,
	keyAudiobookshelfEnable: grantsWhenTrue,
	// A longer session or re-check interval keeps a session, or an account
	// its provider dropped, signed in longer.
	keyAccessTokenExpiry:                  grantsForLonger,
	AuthRefreshTokenExpirySettingKey:      grantsForLonger,
	AuthProviderRecheckIntervalSettingKey: grantsForLonger,
	keyJellyfinSessionTTL:                 grantsForLonger,
	keyJellyfinPlaybackTTL:                grantsForLonger,
}

// Keys of the access settings no other constant names.
const (
	keyJellyfinEnabled      = "jellyfin_compat.enabled"
	keyJellyfinWebEnabled   = "jellyfin_compat.web_enabled"
	keyAudiobookshelfEnable = "audiobookshelf_compat.enabled"
	keyAccessTokenExpiry    = "auth.access_token_expiry" //nolint:gosec // G101: a setting key, not a credential
	keyJellyfinSessionTTL   = "jellyfin_compat.session_ttl"
	keyJellyfinPlaybackTTL  = "jellyfin_compat.playback_session_ttl"
	keySMTPSecurity         = "email.smtp_security"
)

// The email.smtp_security modes, as internal/mail reads them.
const (
	smtpSecurityStartTLS = "starttls"
	smtpSecurityTLS      = "tls"
	smtpSecurityNone     = "none"
)

func grantsWhenTrue(v string) (int64, bool) {
	on, err := strconv.ParseBool(v)
	if err != nil {
		return 0, false
	}
	if on {
		return 1, true
	}
	return 0, true
}

func grantsForLonger(v string) (int64, bool) {
	d, err := parseDuration(v)
	if err != nil || d <= 0 {
		return 0, false
	}
	return int64(d), true
}

// AccessSettingWider reports whether key is an access setting (see
// accessSettings) and, if so, whether restored grants more than live. An
// empty value is the setting's default. A value that does not read counts
// as wider, so the live value stays when the two cannot be compared.
func AccessSettingWider(key, restored, live string) (access, wider bool) {
	grant, ok := accessSettings[key]
	if !ok {
		return false, false
	}
	effective := func(v string) string {
		if v == "" {
			return adminSettingDefaults[key]
		}
		return v
	}
	r, rok := grant(effective(restored))
	l, lok := grant(effective(live))
	return true, !rok || !lok || r > l
}

// AccessSettingKeys lists the access settings, sorted.
func AccessSettingKeys() []string {
	keys := make([]string, 0, len(accessSettings))
	for key := range accessSettings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
