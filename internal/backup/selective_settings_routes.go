package backup

import (
	"fmt"
	"strings"
)

// settingRoute is an outside service's address with the secrets this server
// sends there. A restore never pairs a backup's address with this server's
// secret: the backup's address could be anyone's.
type settingRoute struct {
	endpoint string
	secrets  []string
	// enabled turns the service on; a restore that clears the secrets turns
	// it off until they are entered again.
	enabled string
}

// settingRoutes are the restorable settings that name where a service
// connects together with the secrets it sends there. The S3 and storage
// endpoints, the search engine, AI providers, and the push relay are
// server-specific and never restored; Discord, TMDB, MDBList, IntroDB, and
// the watch providers connect to fixed hosts; a plugin's configuration is
// restored whole or not at all. TestSettingRoutesAreOnOnePage keeps each
// route on one settings page, so one page restores it.
var settingRoutes = []settingRoute{
	{endpoint: "email.smtp_host", secrets: []string{"email.smtp_password"}, enabled: "email.enabled"},
	{endpoint: "ai.base_url", secrets: []string{"ai.api_key"}},
	{endpoint: "ai.asr_base_url", secrets: []string{"ai.asr_api_key"}},
	{endpoint: "subtitle_ai.base_url", secrets: []string{"subtitle_ai.api_key"}},
	{endpoint: "recommendations.embedding_base_url", secrets: []string{"recommendations.embedding_auth_token", "recommendations.openai_api_key"}},
}

// guardRoutes applies settingRoutes to plans: when a restore changes a
// service's address, each of its secrets must come from the backup too.
// One the backup does not have, or that this server cannot read, is cleared
// here rather than sent to the new address, and the service is turned off.
// Every secret of a changed route is expected unchanged under the settings
// lock (settingsUnchanged).
func guardRoutes(plans []settingPlan, live func(key string) string) []settingPlan {
	index := map[string]int{}
	for i, p := range plans {
		index[p.preview.Key] = i
	}
	plan := func(key string) *settingPlan {
		if i, ok := index[key]; ok {
			return &plans[i]
		}
		rule, _ := classifySetting(key)
		plans = append(plans, settingPlan{page: rule.page, live: live(key),
			preview: PreviewSetting{Key: key, Class: rule.class, Masked: true}})
		index[key] = len(plans) - 1
		return &plans[len(plans)-1]
	}
	for _, r := range settingRoutes {
		if i, ok := index[r.endpoint]; !ok || plans[i].preview.Status != ItemDiffers {
			continue
		}
		cleared := false
		for _, key := range r.secrets {
			_, inBackup := index[key]
			p := plan(key)
			p.expect = true
			if inBackup && (p.preview.Status == ItemDiffers || p.preview.Status == ItemOnThisServer) {
				continue
			}
			if live(key) != "" {
				p.preview.Status, p.value, cleared = SettingCleared, "", true
			}
		}
		if cleared && r.enabled != "" && live(r.enabled) != settingOff {
			p := plan(r.enabled)
			p.preview.Masked = false
			p.preview.Status, p.value = SettingCleared, settingOff
			p.preview.BackupValue, p.preview.CurrentValue = settingOff, live(r.enabled)
		}
	}
	return plans
}

// settingCounts tallies a settings page's plans by status.
type settingCounts struct {
	differs, cleared, needsKey, stricter, unverified int
	clearedKeys                                      []string
}

func (c *settingCounts) add(p settingPlan) {
	switch p.preview.Status {
	case ItemDiffers:
		c.differs++
	case SettingCleared:
		c.cleared++
		c.clearedKeys = append(c.clearedKeys, p.preview.Key)
	case ItemNeedsAnotherKey:
		c.needsKey++
	case SettingKeptStricter:
		c.stricter++
	case SettingUnverifiedBackup:
		c.unverified++
	}
}

// writes counts the settings a restore of the page writes.
func (c *settingCounts) writes() int { return c.differs + c.cleared }

// notes says what a restore of the page leaves out or clears, when it
// writes something.
func (c *settingCounts) notes() []string {
	if c.writes() == 0 {
		return nil
	}
	var notes []string
	if c.needsKey > 0 {
		notes = append(notes, fmt.Sprintf("%d encrypted settings on this page were encrypted with another SECRET_KEY and are left out.", c.needsKey))
	}
	if c.stricter > 0 {
		notes = append(notes, keptStricterNote(c.stricter))
	}
	if c.unverified > 0 {
		notes = append(notes, msgUnverifiedServices)
	}
	if c.cleared > 0 {
		notes = append(notes, "A service's address changes without its credentials in the backup, so restoring clears "+
			strings.Join(c.clearedKeys, ", ")+" here (and turns the service off) until they are entered again.")
	}
	return notes
}

// settingOff is a switch setting turned off.
const settingOff = "false"

// msgUnverifiedServices says why settings that connect to outside services
// are left out of an unverified backup's restore.
const msgUnverifiedServices = "Settings that connect to outside services are not restored from a backup this server cannot verify."
