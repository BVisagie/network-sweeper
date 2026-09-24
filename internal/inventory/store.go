package inventory

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Storage modes reported by Status.
const (
	ModePersistent  = "persistent"  // saved under Dir
	ModeEphemeral   = "ephemeral"   // memory only, by choice
	ModeUnavailable = "unavailable" // memory only, because Dir could not be used
)

// Status says where history is kept and, when it is not saved, why.
type Status struct {
	Mode      string `json:"mode"`
	Dir       string `json:"dir,omitempty"`
	Reason    string `json:"reason,omitempty"`
	LastError string `json:"lastError,omitempty"` // most recent failed write, if any
}

const (
	inventoryName = "inventory.json"
	scansDir      = "scans"
	lockName      = "lock"
)

// Store holds the inventory. All methods are safe for concurrent use and
// return copies.
type Store struct {
	mu     sync.Mutex
	dir    string   // empty in memory-only modes
	lock   *os.File // held OS lock on dir/lock
	status Status
	inv    inventoryFile
	snaps  map[string]*Snapshot // memory-only snapshots, and scans that failed to save
}

// Memory returns a store that keeps everything in memory for this session.
func Memory(mode, reason string) *Store {
	return &Store{
		status: Status{Mode: mode, Reason: reason},
		inv:    freshInventory(),
		snaps:  map[string]*Snapshot{},
	}
}

func freshInventory() inventoryFile {
	return inventoryFile{Version: SchemaVersion, Retention: DefaultRetention, Reviews: map[string]*Review{}}
}

// Open uses dir for storage. It never fails: when dir cannot be used (another
// instance holds it, a file is damaged or from a newer version), the store
// runs in memory for this session, leaves the files untouched, and says why in
// Status.
func Open(dir string) *Store {
	if err := os.MkdirAll(filepath.Join(dir, scansDir), 0o700); err != nil {
		return Memory(ModeUnavailable, fmt.Sprintf("Could not create %s: %v. History is kept in memory for this session only.", dir, err))
	}
	lock, err := acquireLock(filepath.Join(dir, lockName))
	if err != nil {
		return Memory(ModeUnavailable, err.Error()+" History is kept in memory for this session only.")
	}
	s := &Store{dir: dir, lock: lock, status: Status{Mode: ModePersistent, Dir: dir}, snaps: map[string]*Snapshot{}}
	inv, err := loadInventory(dir)
	if err != nil {
		lock.Close()
		mem := Memory(ModeUnavailable, err.Error())
		mem.status.Dir = dir
		return mem
	}
	s.inv = inv
	removeTemps(dir)
	removeTemps(filepath.Join(dir, scansDir))
	return s
}

// Close releases the data-directory lock.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil {
		// The lock file stays: removing it could let two processes lock
		// different files of the same name.
		s.lock.Close()
		s.lock = nil
		s.dir = ""
	}
}

// Status reports the storage mode.
func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func loadInventory(dir string) (inventoryFile, error) {
	path := filepath.Join(dir, inventoryName)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return freshInventory(), nil
	}
	if err != nil {
		return inventoryFile{}, fmt.Errorf("Could not read %s: %v. Nothing was changed; history is kept in memory for this session only.", path, err)
	}
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return inventoryFile{}, fmt.Errorf("%s is damaged (%v). Nothing was changed. Move it aside to start a fresh history, or run with --ephemeral.", path, err)
	}
	if head.Version > SchemaVersion {
		return inventoryFile{}, fmt.Errorf("%s was written by a newer version of Network Sweeper (storage version %d; this build reads %d). Nothing was changed; update the app, or run with --data-dir to use another folder.", path, head.Version, SchemaVersion)
	}
	inv := freshInventory()
	if err := json.Unmarshal(b, &inv); err != nil {
		return inventoryFile{}, fmt.Errorf("%s is damaged (%v). Nothing was changed. Move it aside to start a fresh history, or run with --ephemeral.", path, err)
	}
	if inv.Reviews == nil {
		inv.Reviews = map[string]*Review{}
	}
	if inv.Retention <= 0 {
		inv.Retention = DefaultRetention
	}
	// Scans that failed to save lived only in that session's memory.
	kept := inv.Scans[:0]
	for _, e := range inv.Scans {
		if !e.Unsaved {
			kept = append(kept, e)
		}
	}
	inv.Scans = kept
	inv.Version = SchemaVersion
	return inv, nil
}

// writeAtomic replaces path with data via a synced temporary file and rename,
// so a crash leaves either the old file or the new one.
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func removeTemps(dir string) {
	matches, _ := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	for _, m := range matches {
		os.Remove(m)
	}
}

// persist writes the index. Caller holds s.mu.
func (s *Store) persist() error {
	if s.dir == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.inv, "", " ")
	if err == nil {
		err = writeAtomic(filepath.Join(s.dir, inventoryName), b)
	}
	s.noteWrite(err)
	return err
}

func (s *Store) noteWrite(err error) {
	if err != nil {
		s.status.LastError = err.Error()
	} else {
		s.status.LastError = ""
	}
}

func (s *Store) snapshotPath(id string) string {
	return filepath.Join(s.dir, scansDir, id+".json")
}

// validID guards file names built from scan IDs.
func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// Record saves a finished scan: it picks the network profile, links every host
// to a device (setting Host.DeviceID), updates annotations' observations, and
// applies retention. The snapshot is updated in place. A write error is
// returned, but the in-memory inventory still reflects the scan.
func (s *Store) Record(snap *Snapshot) error {
	if !validID(snap.ID) {
		return fmt.Errorf("invalid scan id %q", snap.ID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.profileFor(snap)
	snap.ProfileID = p.ID
	snap.Version = SchemaVersion
	p.LastScan = snap.FinishedAt
	s.inv.LastProfileID = p.ID
	s.assign(p, snap)
	entry := ScanEntry{
		ID: snap.ID, ProfileID: p.ID, StartedAt: snap.StartedAt, FinishedAt: snap.FinishedAt,
		State: snap.State, Partial: snap.Partial, Ranges: snap.Coverage.Ranges, Methods: snap.Coverage.Methods,
		Hosts: len(snap.Hosts), Findings: len(snap.Findings),
	}

	// A scan whose file could not be written stays in memory for this
	// session, so it can still be compared and exported, and retention does
	// not run: older history is never removed while storage is failing.
	var saveErr error
	saved := true
	if s.dir == "" {
		s.snaps[snap.ID] = cloneSnapshot(snap)
	} else {
		b, err := json.Marshal(snap)
		if err == nil {
			err = writeAtomic(s.snapshotPath(snap.ID), b)
		}
		if err != nil {
			saveErr = fmt.Errorf("could not save scan %s: %w", snap.ID, err)
			saved = false
			entry.Unsaved = true
			s.snaps[snap.ID] = cloneSnapshot(snap)
		}
	}
	s.inv.Scans = append(s.inv.Scans, entry)
	var dropped []string
	if saved {
		dropped = s.trimRetention()
	}
	if err := s.persist(); err != nil {
		if saveErr == nil {
			saveErr = fmt.Errorf("could not save the inventory: %w", err)
		}
	} else {
		// Old files go only once the index no longer lists them.
		s.removeSnapshots(dropped)
	}
	s.noteWrite(saveErr)
	return saveErr
}

// trimRetention drops the oldest scans beyond the limit from the index and
// device history, and returns their IDs. Devices and annotations stay. The
// caller deletes the files after the new index is written. Caller holds s.mu.
func (s *Store) trimRetention() []string {
	extra := len(s.inv.Scans) - s.inv.Retention
	if extra <= 0 {
		return nil
	}
	var ids []string
	dropped := map[string]bool{}
	for _, e := range s.inv.Scans[:extra] {
		ids = append(ids, e.ID)
		dropped[e.ID] = true
	}
	s.inv.Scans = append([]ScanEntry(nil), s.inv.Scans[extra:]...)
	for _, d := range s.inv.Devices {
		kept := d.History[:0]
		for _, h := range d.History {
			if !dropped[h.ScanID] {
				kept = append(kept, h)
			}
		}
		d.History = kept
	}
	return ids
}

// removeSnapshots deletes scans that are no longer indexed. Caller holds s.mu.
func (s *Store) removeSnapshots(ids []string) {
	for _, id := range ids {
		delete(s.snaps, id)
		if s.dir != "" {
			os.Remove(s.snapshotPath(id))
		}
	}
}

// Snapshot loads a retained scan.
func (s *Store) Snapshot(id string) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadSnapshot(id)
}

func (s *Store) loadSnapshot(id string) (*Snapshot, error) {
	if !s.hasScan(id) || !validID(id) {
		return nil, fmt.Errorf("scan %s is not in the retained history", id)
	}
	if snap := s.snaps[id]; snap != nil {
		return cloneSnapshot(snap), nil
	}
	if s.dir == "" {
		return nil, fmt.Errorf("scan %s is not available in this session", id)
	}
	b, err := os.ReadFile(s.snapshotPath(id))
	if err != nil {
		return nil, fmt.Errorf("scan %s could not be read: %v", id, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, fmt.Errorf("scan %s is damaged and cannot be compared or exported: %v", id, err)
	}
	if snap.Version > SchemaVersion {
		return nil, fmt.Errorf("scan %s was written by a newer version of Network Sweeper", id)
	}
	return &snap, nil
}

func (s *Store) hasScan(id string) bool {
	for _, e := range s.inv.Scans {
		if e.ID == id {
			return true
		}
	}
	return false
}

// Scans lists retained scans for a profile (all profiles when empty), newest first.
func (s *Store) Scans(profileID string) []ScanEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ScanEntry
	for i := len(s.inv.Scans) - 1; i >= 0; i-- {
		e := s.inv.Scans[i]
		if profileID == "" || e.ProfileID == profileID {
			out = append(out, e)
		}
	}
	return out
}

// Profiles lists known networks, most recently scanned first.
func (s *Store) Profiles() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Profile, 0, len(s.inv.Profiles))
	for _, p := range s.inv.Profiles {
		out = append(out, *p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastScan.After(out[j].LastScan) })
	return out
}

// CurrentProfile is the profile of the most recent scan, or "".
func (s *Store) CurrentProfile() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inv.LastProfileID
}

// RenameProfile sets a profile's display name.
func (s *Store) RenameProfile(id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.inv.Profiles {
		if p.ID == id {
			p.Name = cleanText(name, 80)
			if p.Name == "" {
				p.Name = defaultProfileName(p)
			}
			return s.persist()
		}
	}
	return errNotFound
}

var errNotFound = errors.New("not found")

// IsNotFound reports whether err means the requested item does not exist.
func IsNotFound(err error) bool { return errors.Is(err, errNotFound) }

// Devices lists a profile's devices.
func (s *Store) Devices(profileID string) []Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Device
	for _, d := range s.inv.Devices {
		if d.ProfileID == profileID {
			out = append(out, cloneDevice(d))
		}
	}
	return out
}

// Device returns one device.
func (s *Store) Device(id string) (Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.device(id); d != nil {
		return cloneDevice(d), true
	}
	return Device{}, false
}

func (s *Store) device(id string) *Device {
	for _, d := range s.inv.Devices {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// Annotation is a user edit to a device; nil fields are left alone.
type Annotation struct {
	Name  *string   `json:"name"`
	Notes *string   `json:"notes"`
	Tags  *[]string `json:"tags"`
}

// Annotate updates a device's name, notes, or tags.
func (s *Store) Annotate(id string, a Annotation) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.device(id)
	if d == nil {
		return Device{}, errNotFound
	}
	if a.Name != nil {
		d.Name = cleanText(*a.Name, 80)
	}
	if a.Notes != nil {
		d.Notes = cleanNotes(*a.Notes, 4000)
	}
	if a.Tags != nil {
		d.Tags = cleanTags(*a.Tags)
	}
	return cloneDevice(d), s.persist()
}

// Retention returns how many scans are kept.
func (s *Store) Retention() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inv.Retention
}

// SetRetention changes how many scans are kept and applies it now.
func (s *Store) SetRetention(n int) error {
	if n < 1 || n > 1000 {
		return fmt.Errorf("retention must be between 1 and 1000 scans")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inv.Retention = n
	dropped := s.trimRetention()
	if err := s.persist(); err != nil {
		return err
	}
	s.removeSnapshots(dropped)
	return nil
}

// DeleteHistory removes every saved scan and device history row, keeping
// devices, their names, notes and tags, and finding reviews.
func (s *Store) DeleteHistory() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.inv.Scans {
		if s.dir != "" {
			os.Remove(s.snapshotPath(e.ID))
		}
	}
	s.snaps = map[string]*Snapshot{}
	s.inv.Scans = nil
	for _, d := range s.inv.Devices {
		d.History = nil
	}
	return s.persist()
}

// DeleteAll removes all saved data: scans, devices, annotations, reviews, and
// profiles. Settings such as retention are kept.
func (s *Store) DeleteAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.inv.Scans {
		if s.dir != "" {
			os.Remove(s.snapshotPath(e.ID))
		}
	}
	retention := s.inv.Retention
	s.inv = freshInventory()
	s.inv.Retention = retention
	s.snaps = map[string]*Snapshot{}
	return s.persist()
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func cloneSnapshot(snap *Snapshot) *Snapshot {
	var out Snapshot
	b, _ := json.Marshal(snap)
	_ = json.Unmarshal(b, &out)
	return &out
}

func cloneDevice(d *Device) Device {
	var out Device
	b, _ := json.Marshal(d)
	_ = json.Unmarshal(b, &out)
	return out
}

// cleanText trims s to one line of at most max runes without control characters.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// cleanNotes keeps newlines and tabs but drops other control characters.
func cleanNotes(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

func cleanTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		t = strings.ToLower(cleanText(t, 32))
		if t == "" || seen[t] || len(out) == 20 {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// now is replaced in tests.
var now = func() time.Time { return time.Now().UTC() }
