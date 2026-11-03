package backup

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"
)

const (
	// beforeRestoreRetention keeps a before-restore copy, the recovery point
	// for a full restore, for a week outside the nightly count.
	beforeRestoreRetention = 7 * 24 * time.Hour
	// beforeUpgradeKeep keeps the two newest before-upgrade copies.
	beforeUpgradeKeep = 2
	// incompleteSweepAge is how old an incomplete folder must be before the
	// sweep deletes it.
	incompleteSweepAge = 24 * time.Hour
)

// folder is one backup folder at the destination for this server.
type folder struct {
	id   string
	kind Kind
	at   time.Time
	// manifest is nil for an incomplete folder, and for one whose manifest
	// did not verify (tampered).
	manifest *Manifest
	// tampered is set when the folder's manifest named this server's
	// SECRET_KEY and did not verify: nothing in it is trusted, and the
	// sweep leaves the folder for the admin to look at.
	tampered bool
	// verified is set when the manifest verified under this server's
	// SECRET_KEY, or the service checks none (tests).
	verified bool
	size     int64
	// newest is the latest modification time of any object in the folder.
	newest time.Time
}

// cleanCopy reports whether f is a copy rotation protects: complete, with
// every blob, and verified, so this server can restore it without extra
// flags. An unverified backup never stands in for a verified clean one.
func (f folder) cleanCopy() bool {
	return f.manifest != nil && f.verified && f.manifest.Status() == StatusComplete
}

// planRotation returns the ids rotation deletes. Only folders with a manifest
// are candidates. pinned ids (the source of an active restore) are never
// deleted. Rules:
//
//   - nightly and manual copies beyond keep are deleted oldest first, except
//     that the newest clean copy (cleanCopy) is always kept, even when that
//     keeps one more than keep, so repeated runs with missing blobs, or
//     backups this server cannot verify, cannot rotate away the last copy it
//     can restore with every blob;
//   - before-restore copies are deleted once older than seven days;
//   - before-upgrade copies keep the two newest.
//
// Neither special kind counts toward keep.
func planRotation(folders []folder, keep int, now time.Time, pinned map[string]bool) []string {
	if keep < 1 {
		keep = 1
	}
	byKind := map[Kind][]folder{}
	for _, f := range folders {
		if f.manifest == nil {
			continue
		}
		group := f.kind
		if group == KindManual {
			group = KindNightly
		}
		byKind[group] = append(byKind[group], f)
	}
	for _, list := range byKind {
		sort.Slice(list, func(i, j int) bool { return list[i].at.After(list[j].at) })
	}
	var deletes []string
	drop := func(f folder) {
		if !pinned[f.id] {
			deletes = append(deletes, f.id)
		}
	}
	regular := byKind[KindNightly]
	newestClean := ""
	for _, f := range regular {
		if f.cleanCopy() {
			newestClean = f.id
			break
		}
	}
	for i, f := range regular {
		if i >= keep && f.id != newestClean {
			drop(f)
		}
	}
	for _, f := range byKind[KindBeforeRestore] {
		if now.Sub(f.at) > beforeRestoreRetention {
			drop(f)
		}
	}
	for i, f := range byKind[KindBeforeUpgrade] {
		if i >= beforeUpgradeKeep {
			drop(f)
		}
	}
	sort.Strings(deletes)
	return deletes
}

// planSweep returns incomplete folders (no manifest) whose name and newest
// object are both older than a day. The sweep runs under the subsystem lock,
// so no backup is writing to any folder it sees.
func planSweep(folders []folder, now time.Time) []string {
	var deletes []string
	for _, f := range folders {
		if f.manifest != nil || f.tampered {
			continue
		}
		if now.Sub(f.at) > incompleteSweepAge && now.Sub(f.newest) > incompleteSweepAge {
			deletes = append(deletes, f.id)
		}
	}
	sort.Strings(deletes)
	return deletes
}

// folders lists this server's backup folders at t, reading each manifest
// (listBackupFolders bounds the listing). A folder whose manifest lists an
// object that is not there, or not at its recorded size, is incomplete: a
// delete that stopped partway, which the sweep finishes. One with more
// objects than Silo writes is left alone, like a tampered one.
func (s *Service) folders(ctx context.Context, t target, serverID string) ([]folder, error) {
	listed, err := listBackupFolders(ctx, t, serverPrefix(serverID))
	if err != nil {
		return nil, err
	}
	out := make([]folder, 0, len(listed))
	for _, l := range listed {
		at, kind, _ := ParseFolderName(l.id)
		f := folder{id: l.id, kind: kind, at: at}
		sizes := make(map[string]int64, len(l.objects))
		for _, obj := range l.objects {
			f.size += obj.Size
			if obj.ModTime.After(f.newest) {
				f.newest = obj.ModTime
			}
			sizes[strings.TrimPrefix(obj.Key, folderPrefix(serverID, l.id))] = obj.Size
		}
		if l.overflow {
			f.tampered = true
			slog.WarnContext(ctx, "backup folder holds more objects than a backup writes; leaving it alone", "component", "backup", "id", l.id)
			out = append(out, f)
			continue
		}
		if _, ok := sizes[ManifestName]; ok {
			m, err := s.readManifest(ctx, t, serverID, l.id)
			switch {
			case err != nil:
				f.tampered = errors.Is(err, ErrManifestTampered)
				slog.WarnContext(ctx, "unreadable backup manifest", "component", "backup", "id", l.id, "error", err)
			case !m.objectsPresent(sizes):
				slog.WarnContext(ctx, "backup manifest lists objects that are gone; the folder is incomplete", "component", "backup", "id", l.id)
			default:
				f.manifest, f.verified = m, m.authenticated || s.opts.ManifestKey == nil
			}
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].at.After(out[j].at) })
	return out, nil
}

// objectsPresent reports whether every object m lists is in sizes (a
// folder's listing, by name) at its recorded size.
func (m *Manifest) objectsPresent(sizes map[string]int64) bool {
	for _, o := range m.Objects {
		if size, ok := sizes[o.Name]; !ok || size != o.Size {
			return false
		}
	}
	return true
}
