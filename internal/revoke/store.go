package revoke

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Store keeps the revocation list on disk, so a restart cannot make a revoked
// token live again.
//
// It is operational state, not evidence. The evidence is the delegation_revoked
// event, where SPEC 6.1 lets one be filed, and the log line every revocation
// writes. What this file adds is the one property the list lacked: a restart
// that forgets would reopen the incident the revocation closed.
type Store struct {
	mu sync.Mutex
	f  *os.File
	// broken is set by the first failed write. From then on every write is
	// refused, so a partial line can only ever be the LAST line, which is the
	// one shape OpenStore knows how to discard.
	broken error
}

// Loaded is what OpenStore found, for the startup log line.
type Loaded struct {
	Active   []Entry
	Expired  int
	TornTail bool
	// Standing is every ban whose revocation half has expired while the ban
	// itself still stands (invariant 25): it carries no list entry, and the
	// startup restores it into the list's bans all the same.
	Standing []Entry
}

// OpenStore reads every entry at path, keeps the ones still load-bearing at
// now, rewrites the file with only those, and returns a Store that appends.
//
// A line that does not parse, or that names nobody, refuses the start: a store
// this process cannot read completely may be hiding a revocation, and starting
// without it would un-revoke. The one exception is the LAST line of a file
// that does not end in a newline: that is a write that died before its fsync
// returned, so no caller was ever told it was durable.
func OpenStore(path string, now time.Time) (*Store, Loaded, error) {
	var got Loaded
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path, read once at startup
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, got, fmt.Errorf("reading VOUCHRYX_REVOCATIONS_PATH at %s: %w", path, err)
	}
	lines := bytes.Split(raw, []byte("\n"))
	// Bans by subject, in file order: a later ban replaces an earlier one and
	// a lift removes it. Applied as the file is read, so the file's own order
	// is the history and compaction keeps only its result.
	bans := map[string]Entry{}
	for i, l := range lines {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(l, &e); err != nil {
			if i == len(lines)-1 {
				got.TornTail = true
				continue
			}
			return nil, got, fmt.Errorf("VOUCHRYX_REVOCATIONS_PATH %s line %d is not a revocation, "+
				"and starting without it could un-revoke a token: %w", path, i+1, err)
		}
		if !whole(e) {
			return nil, got, fmt.Errorf("VOUCHRYX_REVOCATIONS_PATH %s line %d names no token or subject, "+
				"or no actor, reason or expiry, or is a ban or a lift of a shape this service never writes", path, i+1)
		}
		if e.Lift {
			// The ban ends; its revocation half, if still active, stays as an
			// ordinary subject entry, because a lift never un-revokes.
			delete(bans, e.Subject)
			for j := range got.Active {
				if got.Active[j].Subject == e.Subject {
					got.Active[j].Ban = false
				}
			}
			continue
		}
		if e.Ban {
			bans[e.Subject] = e
		}
		if e.Expires <= now.Unix() {
			if !e.Ban {
				got.Expired++
			}
			continue
		}
		got.Active = append(got.Active, e)
	}
	// A ban still standing whose own line is not in Active (its revocation
	// half expired) is Standing. One whose ban was replaced by a later ban of
	// the same subject keeps only the later one.
	for j := range got.Active {
		if got.Active[j].Ban {
			if b, ok := bans[got.Active[j].Subject]; !ok || b != got.Active[j] {
				got.Active[j].Ban = false
			}
		}
	}
	for _, b := range bans {
		if b.Expires <= now.Unix() {
			got.Standing = append(got.Standing, b)
		}
	}
	sort.Slice(got.Standing, func(i, j int) bool { return got.Standing[i].Subject < got.Standing[j].Subject })
	if err := rewrite(path, append(append([]Entry{}, got.Active...), got.Standing...)); err != nil {
		return nil, got, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- the same operator-supplied path
	if err != nil {
		return nil, got, fmt.Errorf("opening VOUCHRYX_REVOCATIONS_PATH at %s: %w", path, err)
	}
	return &Store{f: f}, got, nil
}

// whole is the shape revokeHandler always writes: a token or a subject (a
// subject with its moment), an actor, a reason and an expiry. A ban is a
// subject entry with its moment and no token; a lift names a subject, an
// actor and a reason, and neither a token nor a moment.
func whole(e Entry) bool {
	if e.Actor == "" || e.Reason == "" {
		return false
	}
	switch {
	case e.Lift:
		return !e.Ban && e.JTI == "" && e.Subject != "" && e.IssuedBefore == 0
	case e.Ban:
		return e.JTI == "" && e.Subject != "" && e.IssuedBefore > 0 && e.Expires > 0
	}
	if e.Expires <= 0 {
		return false
	}
	if e.JTI != "" {
		return true
	}
	return e.Subject != "" && e.IssuedBefore > 0
}

// Append writes one entry and returns only after the bytes reached the disk.
// The handler answers 200 after this returns and not before, which is what
// makes "the caller was told" and "the line is whole" the same fact.
func (s *Store) Append(e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	if _, err := s.f.Write(append(b, '\n')); err != nil {
		s.broken = fmt.Errorf("the revocation store stopped taking writes after: %w", err)
		return s.broken
	}
	if err := s.f.Sync(); err != nil {
		s.broken = fmt.Errorf("the revocation store stopped taking writes after: %w", err)
		return s.broken
	}
	return nil
}

// Close releases the file.
func (s *Store) Close() error { return s.f.Close() }

// rewrite replaces the file with exactly these entries: a temporary file in the
// same directory, synced, then renamed over the old one, so a crash leaves the
// old file or the new one and never half of either.
func rewrite(path string, entries []Entry) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vouchryx-revocations-*")
	if err != nil {
		return fmt.Errorf("compacting VOUCHRYX_REVOCATIONS_PATH in %s: %w", dir, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // fails harmlessly once renamed
	w := bufio.NewWriter(tmp)
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			_ = tmp.Close()
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("compacting VOUCHRYX_REVOCATIONS_PATH at %s: %w", path, err)
	}
	// Best effort, on purpose. The rename is atomic and both files were synced;
	// if the directory entry itself is lost in a crash right now, what remains
	// is the previous file, which holds every entry this one does plus expired
	// ones. Nothing is un-revoked. Some platforms refuse fsync on a directory.
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the directory of the operator-supplied path
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
