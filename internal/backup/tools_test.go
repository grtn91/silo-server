package backup

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// TestWithDatabase: a URL derived for another database names only that
// database, however the original named its own, and the name read back is
// the one libpq and pgx connect to. A connection service is refused.
func TestWithDatabase(t *testing.T) {
	cases := []struct {
		name, in, live, out string
	}{
		{name: "path", in: "postgres://silo@db/live?sslmode=disable", live: "live",
			out: "postgres://silo@db/other?sslmode=disable"},
		{name: "query", in: "postgres://silo@db?dbname=live", live: "live", out: "postgres://silo@db/other"},
		{name: "query overrides path", in: "postgres://silo@db/path?dbname=live&host=db2", live: "live",
			out: "postgres://silo@db/other?host=db2"},
		{name: "key value", in: "host=db dbname=first dbname='live one'", live: "live one",
			out: "host='db' dbname='other'"},
		{name: "key value without database", in: "host=db", out: "host='db' dbname='other'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if live, err := databaseName(tc.in); tc.live != "" && (err != nil || live != tc.live) {
				t.Errorf("databaseName = %q, %v; want %q", live, err, tc.live)
			}
			out, err := WithDatabase(tc.in, "other")
			if err != nil || out != tc.out {
				t.Fatalf("WithDatabase = %q, %v; want %q", out, err, tc.out)
			}
			if name, err := databaseName(out); err != nil || name != "other" {
				t.Errorf("databaseName of the result = %q, %v; want other", name, err)
			}
		})
	}
	for _, bad := range []string{"postgres://silo@db/live?service=prod", "postgres:///?servicefile=/etc/pg_service.conf",
		"service=prod dbname=live", "postgres://silo@db/a?dbname=b&dbname=c"} {
		if _, err := databaseName(bad); err == nil {
			t.Errorf("databaseName(%q) accepted it", bad)
		}
	}
	for _, bad := range []string{"postgres://silo@db/live?service=prod", "service=prod dbname=live"} {
		if _, err := WithDatabase(bad, "other"); err == nil || !strings.Contains(err.Error(), "service") {
			t.Errorf("WithDatabase(%q) = %v, want a refusal naming the service", bad, err)
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

// TestCheckSeparateTargets: a separate restore writes only into a new or
// empty directory that is not the live server's storage, and never into
// the live database, however its URL is written.
func TestCheckSeparateTargets(t *testing.T) {
	empty, full, live := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "kept.webp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(live, link); err != nil {
		t.Fatal(err)
	}
	const liveURL = "postgres://silo@db:5432/silo"
	cases := []struct {
		name string
		opts SeparateOptions
		want string
	}{
		{name: "new directory", opts: SeparateOptions{Into: "postgres://silo@db/copy", BlobsInto: filepath.Join(empty, "new")}},
		{name: "empty directory", opts: SeparateOptions{Into: "postgres://silo@db/copy", BlobsInto: empty, LiveURL: liveURL}},
		{name: "directory with files", opts: SeparateOptions{Into: "postgres://silo@db/copy", BlobsInto: full}, want: "not empty"},
		{name: "live storage through a link", opts: SeparateOptions{Into: "postgres://silo@db/copy", BlobsInto: link, LiveBlobRoots: []string{live}},
			want: "own file storage"},
		{name: "live database", opts: SeparateOptions{Into: "host=db port=5432 user=silo dbname=silo", DatabaseOnly: true, LiveURL: liveURL},
			want: "own database"},
		{name: "live database by query", opts: SeparateOptions{Into: "postgres://silo@db/other?dbname=silo", DatabaseOnly: true, LiveURL: liveURL},
			want: "own database"},
		{name: "database only skips files", opts: SeparateOptions{Into: "postgres://silo@db/copy", BlobsInto: full, DatabaseOnly: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSeparateTargets(tc.opts)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("checkSeparateTargets = %v, want %q", err, tc.want)
			}
		})
	}
}
