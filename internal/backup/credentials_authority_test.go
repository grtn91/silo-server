package backup

import (
	"reflect"
	"testing"

	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/requests"
)

// TestAuthorityComparisonCoversEveryField: every field of the policies an
// account's or a grant's authority is compared by widens it when loosened,
// so a new field cannot reach a restore without a decision. A field
// deliberately left out is listed with why.
func TestAuthorityComparisonCoversEveryField(t *testing.T) {
	ten, two := 10, 2
	strictAccess := access.EffectiveUserPolicy{LibraryIDs: []int{1}, MaxPlaybackQuality: "720p", MaxStreams: 1, MaxTranscodes: 1,
		MaxRemoteStreamBitrateKbps: 1000, MaxLocalStreamBitrateKbps: 1000, MaxProfiles: 1, Permissions: []string{}}
	accessWidenings := map[string]func(*access.EffectiveUserPolicy){
		"LibraryIDs":                 func(p *access.EffectiveUserPolicy) { p.LibraryIDs = nil },
		"MaxPlaybackQuality":         func(p *access.EffectiveUserPolicy) { p.MaxPlaybackQuality = "" },
		"DownloadAllowed":            func(p *access.EffectiveUserPolicy) { p.DownloadAllowed = true },
		"DownloadTranscodeAllowed":   func(p *access.EffectiveUserPolicy) { p.DownloadTranscodeAllowed = true },
		"TranscodeAllowed":           func(p *access.EffectiveUserPolicy) { p.TranscodeAllowed = true },
		"AudioTranscodeAllowed":      func(p *access.EffectiveUserPolicy) { p.AudioTranscodeAllowed = true },
		"MaxStreams":                 func(p *access.EffectiveUserPolicy) { p.MaxStreams = 0 },
		"MaxTranscodes":              func(p *access.EffectiveUserPolicy) { p.MaxTranscodes = 0 },
		"MaxRemoteStreamBitrateKbps": func(p *access.EffectiveUserPolicy) { p.MaxRemoteStreamBitrateKbps = 0 },
		"MaxLocalStreamBitrateKbps":  func(p *access.EffectiveUserPolicy) { p.MaxLocalStreamBitrateKbps = 0 },
		"MaxProfiles":                func(p *access.EffectiveUserPolicy) { p.MaxProfiles = 5 },
		"Permissions":                func(p *access.EffectiveUserPolicy) { p.Permissions = []string{"marker_edit"} },
		"RequestsAllowed":            func(p *access.EffectiveUserPolicy) { p.RequestsAllowed = true },
	}
	for _, f := range reflect.VisibleFields(reflect.TypeFor[access.EffectiveUserPolicy]()) {
		widen, ok := accessWidenings[f.Name]
		if !ok {
			t.Errorf("access policy field %s has no widening case: add one, and compare it in access.WiderThan", f.Name)
			continue
		}
		loose := strictAccess
		widen(&loose)
		if len(access.WiderThan(loose, strictAccess)) == 0 {
			t.Errorf("access.WiderThan misses a looser %s", f.Name)
		}
	}

	strictRequests := requests.EffectivePolicy{RequestsEnabled: true, MaxRequests: 2, WindowDays: 10}
	requestWidenings := map[string]func(*requests.EffectivePolicy){
		"RequestsEnabled": nil, // compared against a live policy that has it off, below
		"MaxRequests":     func(p *requests.EffectivePolicy) { p.MaxRequests = ten },
		"WindowDays":      func(p *requests.EffectivePolicy) { p.WindowDays = two },
		"Unlimited":       func(p *requests.EffectivePolicy) { p.Unlimited = true },
		"Blocked":         nil, // as RequestsEnabled
		"AutoApprove":     func(p *requests.EffectivePolicy) { p.AutoApprove = true },
	}
	// Usage, not authority.
	usage := map[string]bool{"Used": true, "Remaining": true, "WindowStart": true}
	for _, f := range reflect.VisibleFields(reflect.TypeFor[requests.EffectivePolicy]()) {
		widen, ok := requestWidenings[f.Name]
		switch {
		case usage[f.Name]:
		case !ok:
			t.Errorf("request policy field %s has no widening case: add one, and compare it in requestsWider", f.Name)
		case widen != nil:
			loose := strictRequests
			widen(&loose)
			if !requestsWider(loose, strictRequests) {
				t.Errorf("requestsWider misses a looser %s", f.Name)
			}
		}
	}
	for name, live := range map[string]requests.EffectivePolicy{
		"RequestsEnabled": {MaxRequests: 2, WindowDays: 10},
		"Blocked":         {RequestsEnabled: true, Blocked: true, MaxRequests: 2, WindowDays: 10},
	} {
		if !requestsWider(strictRequests, live) {
			t.Errorf("requestsWider misses requests allowed where live has %s", name)
		}
	}

	// The account's own fields, each compared by widerThan.
	accountFields := map[string]bool{"rank": true, "enabled": true, "breakGlass": true, "policy": true, "requests": true, "profiles": true}
	for _, f := range reflect.VisibleFields(reflect.TypeFor[accountAuthority]()) {
		if !accountFields[f.Name] {
			t.Errorf("accountAuthority field %s is not compared: add it to widerThan and here", f.Name)
		}
	}
	profileFields := map[string]bool{"child": true, "ceiling": true, "advisoryAge": true, "requireAdvisoryAge": true, "restricted": true, "libraries": true}
	for _, f := range reflect.VisibleFields(reflect.TypeFor[profileLimits]()) {
		if !profileFields[f.Name] {
			t.Errorf("profileLimits field %s is not compared: add it to looserThan and here", f.Name)
		}
	}
}
