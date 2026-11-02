package backup

import (
	"slices"
	"testing"
)

// The password never reaches pg_dump's command line, where ps shows it.
func TestLibpqTargetMovesThePasswordToTheEnvironment(t *testing.T) {
	cases := []struct {
		name, in, dbname string
		conn             string
		env              []string
	}{
		{
			name: "url",
			in:   "postgres://silo:s%40cret@db:5432/silo?sslmode=disable&pool_max_conns=4",
			conn: "postgres://silo@db:5432/silo?sslmode=disable",
			env:  []string{"PGPASSWORD=s@cret"},
		},
		{
			name: "url query password",
			in:   "postgres://silo@db/silo?password=pw",
			conn: "postgres://silo@db/silo",
			env:  []string{"PGPASSWORD=pw"},
		},
		{
			name:   "key value with substituted database",
			in:     "host=db user=silo password=pw dbname=silo pool_max_conns=4",
			dbname: "silo_restore",
			conn:   "host='db' user='silo' dbname='silo_restore'",
			env:    []string{"PGPASSWORD=pw"},
		},
		{
			name: "key value spaced and escaped",
			in:   `host = db  user=si\ lo password = 'p w'`,
			conn: "host='db' user='si lo'",
			env:  []string{"PGPASSWORD=p w"},
		},
		{
			name: "key value quoted password",
			in:   `password='a \'b\\ c' host=db`,
			conn: "host='db'",
			env:  []string{`PGPASSWORD=a 'b\ c`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, env, err := libpqTarget(tc.in, tc.dbname)
			if err != nil {
				t.Fatalf("libpqTarget: %v", err)
			}
			if conn != tc.conn {
				t.Errorf("conn = %q, want %q", conn, tc.conn)
			}
			if !slices.Equal(env, tc.env) {
				t.Errorf("env = %q, want %q", env, tc.env)
			}
		})
	}
	for _, bad := range []string{"host=db password='unterminated", "host", "=db"} {
		if _, _, err := libpqTarget(bad, ""); err == nil {
			t.Errorf("libpqTarget(%q) accepted a malformed connection string", bad)
		}
	}
}

// A database URL with a password is refused on the command line, where
// every account on the host can read it.
func TestHasPassword(t *testing.T) {
	for dsn, want := range map[string]bool{
		"postgres://silo:pw@db/silo":          true,
		"postgres://silo@db/silo?password=pw": true,
		"postgres://silo@db/silo":             false,
		"host=db user=silo password='p w'":    true,
		"host=db user=silo dbname=silo":       false,
		"host=db password='unterminated":      true,
	} {
		if got := HasPassword(dsn); got != want {
			t.Errorf("HasPassword(%q) = %v, want %v", dsn, got, want)
		}
	}
}
