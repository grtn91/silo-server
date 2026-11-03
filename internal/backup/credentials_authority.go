package backup

import (
	"context"
	"encoding/json"
	"errors"
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

// inviteeGrant is what an account created from an invitation or an invite
// code gets: a role, the invitation's libraries, and an access group (the
// default group when none is named, unless the role is admin).
type inviteeGrant struct {
	role       string
	libraryIDs []int
	groupID    *int64
}

// grantOf reads the grant of a carried row of table, if it grants one.
func grantOf(table string, row map[string]any) (inviteeGrant, bool) {
	switch table {
	case "invite_codes":
		return inviteeGrant{role: models.RoleUser}, true
	case "plugin_auth_bindings":
		// An account a provider creates is a user in the default group
		// (auth.AccountResolver); one the provider makes an admin is the
		// provider's decision, on both servers alike.
		on, _ := row[columnAutoProvision].(bool)
		return inviteeGrant{role: models.RoleUser}, on
	case "invitations":
		g := inviteeGrant{role: models.RoleUser}
		if role, ok := row["role"].(string); ok {
			g.role = role
		}
		if ids, ok := row["library_ids"].([]any); ok {
			g.libraryIDs = []int{}
			for _, id := range ids {
				if n, ok := id.(float64); ok {
					g.libraryIDs = append(g.libraryIDs, int(n))
				}
			}
		}
		if id, ok := row["access_group_id"].(float64); ok {
			g.groupID = new(int64(id))
		}
		return g, true
	}
	return inviteeGrant{}, false
}

// inviteePolicy is the effective policy an account created now from g
// would get in tx's database, as account creation resolves it.
func inviteePolicy(ctx context.Context, tx pgx.Tx, g inviteeGrant) (access.EffectiveUserPolicy, error) {
	// The permissions account creation stores (auth.NewUserPermissions), so
	// a group's allowed permissions mask the same list here as there.
	permissions, err := auth.NewUserPermissions(models.CreateUserInput{Role: g.role, LibraryIDs: g.libraryIDs, AccessGroupID: g.groupID})
	if err != nil {
		return access.EffectiveUserPolicy{}, err
	}
	user := &models.User{Role: g.role, LibraryIDs: g.libraryIDs, AccessGroupID: g.groupID, Permissions: permissions}
	if user.AccessGroupID == nil && g.role != models.RoleAdmin {
		var id int64
		err := tx.QueryRow(ctx, `SELECT id FROM access_groups WHERE is_default`).Scan(&id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return access.EffectiveUserPolicy{}, fmt.Errorf("reading the default access group: %w", err)
		}
		if err == nil {
			user.AccessGroupID = &id
		}
	}
	if !access.GroupApplies(user) {
		return access.ApplyGroupPolicy(user, nil), nil
	}
	group, err := access.ReadGroupInTransaction(ctx, tx, *user.AccessGroupID)
	if errors.Is(err, access.ErrGroupNotFound) {
		// The carry drops an invitation whose group is gone.
		return access.ApplyGroupPolicy(user, nil), nil
	}
	if err != nil {
		return access.EffectiveUserPolicy{}, fmt.Errorf("reading access group %d: %w", *user.AccessGroupID, err)
	}
	policy := group.Policy()
	return access.ApplyGroupPolicy(user, &policy), nil
}

// grantKey names a carried row that grants an account: its table and id.
type grantKey struct {
	table string
	id    int64
}

// inviteePolicies reads, in tx's database, the policy each carried row
// that grants an account would give it.
func inviteePolicies(ctx context.Context, tx pgx.Tx, tables []secretTable, live []string) (map[grantKey]access.EffectiveUserPolicy, error) {
	out := map[grantKey]access.EffectiveUserPolicy{}
	for i, t := range tables {
		var rows []map[string]any
		if err := json.Unmarshal([]byte(live[i]), &rows); err != nil {
			return nil, fmt.Errorf("%s: %w", t.name, err)
		}
		for _, row := range rows {
			g, ok := grantOf(t.name, row)
			id, hasID := row["id"].(float64)
			if !ok || !hasID {
				continue
			}
			policy, err := inviteePolicy(ctx, tx, g)
			if err != nil {
				return nil, err
			}
			out[grantKey{table: t.name, id: int64(id)}] = policy
		}
	}
	return out, nil
}
