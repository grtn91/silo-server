package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/models"
)

// accountAuthority is what an account may do: its rank (the Owner over
// admin over user), whether it can sign in, break-glass access, its
// effective account policy, and its profiles' restrictions by profile id.
type accountAuthority struct {
	rank       int
	enabled    bool
	breakGlass bool
	policy     access.EffectiveUserPolicy
	profiles   map[string]profileLimits
}

// profileLimits are a profile's restrictions: a child profile, its rating
// and advisory-age ceilings, and its library restriction.
type profileLimits struct {
	child              bool
	ceiling            string
	advisoryAge        *int
	requireAdvisoryAge bool
	restricted         bool
	libraries          []int
}

// readAuthority reads the authority of the accounts ids in tx's database;
// an account that is not there is left out.
func readAuthority(ctx context.Context, tx pgx.Tx, ids []int) (map[int]accountAuthority, error) {
	out := map[int]accountAuthority{}
	for _, id := range ids {
		user, err := auth.UserInTransaction(ctx, tx, id)
		if auth.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading account %d: %w", id, err)
		}
		var group *access.GroupPolicy
		if access.GroupApplies(user) {
			if group, err = access.GroupPolicyInTransaction(ctx, tx, id); err != nil {
				return nil, fmt.Errorf("reading account %d's access group: %w", id, err)
			}
		}
		a := accountAuthority{rank: roleRank(user), enabled: user.Enabled, breakGlass: user.BreakGlass,
			policy: access.ApplyGroupPolicy(user, group)}
		if a.profiles, err = readProfileLimits(ctx, tx, id); err != nil {
			return nil, err
		}
		out[id] = a
	}
	return out, nil
}

func roleRank(user *models.User) int {
	switch {
	case user.IsOwner:
		return 2
	case user.Role == models.RoleAdmin:
		return 1
	}
	return 0
}

func readProfileLimits(ctx context.Context, tx pgx.Tx, userID int) (map[string]profileLimits, error) {
	rows, err := tx.Query(ctx, `
		SELECT p.id, p.is_child, coalesce(p.max_content_rating, ''), p.max_advisory_age::int, p.require_advisory_age,
			p.library_restrictions_enabled,
			coalesce((SELECT array_agg(a.library_id ORDER BY a.library_id) FROM user_profile_allowed_libraries a WHERE a.profile_id = p.id), '{}')
		FROM user_profiles p WHERE p.user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("reading account %d's profiles: %w", userID, err)
	}
	defer rows.Close()
	out := map[string]profileLimits{}
	for rows.Next() {
		var id string
		var p profileLimits
		if err := rows.Scan(&id, &p.child, &p.ceiling, &p.advisoryAge, &p.requireAdvisoryAge, &p.restricted, &p.libraries); err != nil {
			return nil, err
		}
		out[id] = p
	}
	return out, rows.Err()
}

// widerThan reports whether restored grants anything live does not: a
// higher rank, sign-in or break-glass access live lacks, a wider account
// policy (access.WiderThan), or a profile on both sides with a restriction
// lifted or loosened. A profile only the restored data has is not compared:
// the account restores it whatever its credentials.
func (restored accountAuthority) widerThan(live accountAuthority) bool {
	if restored.rank > live.rank || restored.enabled && !live.enabled || restored.breakGlass && !live.breakGlass ||
		len(access.WiderThan(restored.policy, live.policy)) > 0 {
		return true
	}
	for id, r := range restored.profiles {
		if l, ok := live.profiles[id]; ok && r.looserThan(l) {
			return true
		}
	}
	return false
}

func (p profileLimits) looserThan(live profileLimits) bool {
	if live.child && !p.child || live.requireAdvisoryAge && !p.requireAdvisoryAge {
		return true
	}
	if access.HasCeiling(live.ceiling) && p.ceiling != live.ceiling {
		liveAge, ok := access.AgeForCeiling(live.ceiling)
		age, known := access.AgeForCeiling(p.ceiling)
		if !access.HasCeiling(p.ceiling) || !ok || !known || *age > *liveAge {
			return true
		}
	}
	if live.advisoryAge != nil && (p.advisoryAge == nil || *p.advisoryAge > *live.advisoryAge) {
		return true
	}
	if live.restricted {
		if !p.restricted {
			return true
		}
		for _, id := range p.libraries {
			if !slices.Contains(live.libraries, id) {
				return true
			}
		}
	}
	return false
}

// credentialOwners lists the accounts the live rows of the carried tables
// belong to, by their owner columns.
func credentialOwners(tables []secretTable, live []string) ([]int, error) {
	var ids []int
	for i, t := range tables {
		if len(t.carry.owners) == 0 {
			continue
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(live[i]), &rows); err != nil {
			return nil, fmt.Errorf("%s: %w", t.name, err)
		}
		for _, row := range rows {
			for _, column := range t.carry.owners {
				if id, ok := row[column].(float64); ok {
					ids = append(ids, int(id))
				}
			}
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}
