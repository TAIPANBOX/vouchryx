package revoke

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func storePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "revocations.ndjson")
}

func line(jti string, expires int64) string {
	return `{"jti":"` + jti + `","expires":` + strconv.FormatInt(expires, 10) +
		`,"actor":"user://a/b","reason":"r"}`
}

func reopen(t *testing.T, path string, now time.Time) *List {
	t.Helper()
	st, got, err := OpenStore(path, now)
	if err != nil {
		t.Fatalf("reopening the store: %v", err)
	}
	_ = st.Close()
	l := New()
	for _, e := range got.Active {
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func TestAMissingFileStartsEmpty(t *testing.T) {
	st, got, err := OpenStore(storePath(t), time.Now())
	if err != nil {
		t.Fatalf("a first start with no file refused: %v", err)
	}
	defer st.Close()
	if len(got.Active) != 0 || got.Expired != 0 || got.TornTail {
		t.Fatalf("a missing file loaded %+v", got)
	}
}

func TestARevocationSurvivesAReopen(t *testing.T) {
	path, now := storePath(t), time.Now()
	st, _, err := OpenStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{JTI: "leaked", Expires: now.Add(time.Hour).Unix(), Actor: "user://a/b", Reason: "seen in a log"}
	if err := st.Append(e); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if _, ok := reopen(t, path, now).Revoked("leaked", "agent://a/one", now.Unix(), now); !ok {
		t.Fatal("a revocation written before the reopen did not survive it")
	}
}

func TestASubjectRevocationKeepsItsMomentAcrossAReopen(t *testing.T) {
	path, now := storePath(t), time.Now()
	st, _, err := OpenStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	moment := now.Unix()
	e := Entry{Subject: "agent://a/x", IssuedBefore: moment, Expires: now.Add(time.Hour).Unix(),
		Actor: "user://a/b", Reason: "credential in a paste"}
	if err := st.Append(e); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	l := reopen(t, path, now)
	if _, ok := l.Revoked("j", "agent://a/x", moment, now); !ok {
		t.Fatal("a token minted in the revocation's own second survived the reopen")
	}
	if _, ok := l.Revoked("j", "agent://a/x", moment+1, now); ok {
		t.Fatal("after the reopen the revocation also killed a token issued after its moment")
	}
}

func TestAnExpiredEntryIsDroppedAndTheFileCompacted(t *testing.T) {
	path, now := storePath(t), time.Now()
	body := line("live", now.Add(time.Hour).Unix()) + "\n" + line("dead", now.Add(-time.Minute).Unix()) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	st, got, err := OpenStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if got.Expired != 1 || len(got.Active) != 1 || got.Active[0].JTI != "live" {
		t.Fatalf("loaded %+v; want one active (live) and one expired", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"dead"`) {
		t.Fatalf("the compacted file still holds the expired entry: %s", raw)
	}
}

func TestAMalformedLineThatIsNotTheLastRefusesToOpen(t *testing.T) {
	path, now := storePath(t), time.Now()
	good := line("a", now.Add(time.Hour).Unix())
	if err := os.WriteFile(path, []byte(good+"\n{not json\n"+good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStore(path, now); err == nil {
		t.Fatal("a store with an unreadable record before its last line opened; it must refuse rather than forget")
	}
}

func TestATornLastLineIsDiscardedAndReported(t *testing.T) {
	path, now := storePath(t), time.Now()
	body := line("a", now.Add(time.Hour).Unix()) + "\n" + `{"jti":"b","expi`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	st, got, err := OpenStore(path, now)
	if err != nil {
		t.Fatalf("a half-written last line refused the start: %v", err)
	}
	_ = st.Close()
	if !got.TornTail || len(got.Active) != 1 || got.Active[0].JTI != "a" {
		t.Fatalf("loaded %+v; want the whole record kept and the torn one reported", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"b"`) {
		t.Fatalf("the torn record is still in the file after the start: %s", raw)
	}
}

func TestAnEntryNamingNobodyRefusesToOpen(t *testing.T) {
	path, now := storePath(t), time.Now()
	body := `{"expires":` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) +
		`,"actor":"user://a/b","reason":"r"}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStore(path, now); err == nil {
		t.Fatal("a record naming neither a token nor a subject opened; the only writer never writes one")
	}
}

// Every way the file can be cut short, at every byte, either loads a prefix of
// what was written (the cut record discarded as torn) or refuses the start. It
// never loads a record nobody wrote and never panics.
func TestEveryTruncationEitherLoadsAPrefixOrRefuses(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	full := line("a", exp) + "\n" + line("b", exp) + "\n" + line("c", exp) + "\n"
	want := []string{"a", "b", "c"}
	for cut := 0; cut <= len(full); cut++ {
		path := storePath(t)
		if err := os.WriteFile(path, []byte(full[:cut]), 0o600); err != nil {
			t.Fatal(err)
		}
		st, got, err := OpenStore(path, now)
		if err != nil {
			continue // refusing the start is an allowed answer
		}
		_ = st.Close()
		for i, e := range got.Active {
			if i >= len(want) || e.JTI != want[i] {
				t.Fatalf("cut at byte %d loaded %+v, which is not a prefix of what was written", cut, got.Active)
			}
		}
	}
}

// VOUCHRYX_REVOCATIONS_PATH naming an existing directory is an operator
// mistake, not an empty store: a service that read this as "no file yet" and
// carried on would look healthy while keeping no revocations at all.
func TestAStorePathThatIsADirectoryRefusesToOpen(t *testing.T) {
	dir := t.TempDir()
	asDir := filepath.Join(dir, "revocations-is-a-dir")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenStore(asDir, time.Now()); err == nil {
		t.Fatal("a store path that is a directory opened; it must refuse rather than silently keep no revocations")
	}
}

// A parent directory that does not exist is the same shape of mistake: this
// service reads its store path from the environment and does not create
// directories on the operator's behalf.
func TestAStorePathInAMissingDirectoryRefusesToOpen(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "does-not-exist")
	path := filepath.Join(parent, "revocations.ndjson")
	if _, _, err := OpenStore(path, time.Now()); err == nil {
		t.Fatal("a store whose parent directory does not exist opened; it must refuse rather than silently keep no revocations")
	}
	if _, err := os.Stat(parent); err == nil {
		t.Fatal("OpenStore created the missing parent directory; it must refuse instead of making one")
	}
}

func TestAFailedWriteStopsLaterWritesRatherThanCorruptingTheFile(t *testing.T) {
	path, now := storePath(t), time.Now()
	st, _, err := OpenStore(path, now)
	if err != nil {
		t.Fatal(err)
	}
	good := st.f
	readOnly, err := os.Open(path) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	st.f = readOnly // every write fails, as a full disk would
	e := Entry{JTI: "a", Expires: now.Add(time.Hour).Unix(), Actor: "user://a/b", Reason: "r"}
	if err := st.Append(e); err == nil {
		t.Fatal("a write that could not happen reported success")
	}
	st.f = good // the disk recovered
	if err := st.Append(e); err == nil {
		t.Fatal("a write after a failed one went through; a torn line behind it would corrupt the file")
	}
	_ = good.Close()
	_ = readOnly.Close()
}
