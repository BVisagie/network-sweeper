package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/BVisagie/network-sweeper/internal/risk"
)

// ReviewState is a finding's review status as shown to the user.
type ReviewState struct {
	Status string `json:"status"` // open | acknowledged | reopened
	Note   string `json:"note,omitempty"`
	At     string `json:"at,omitempty"`
}

func reviewKey(deviceID, findingKey string) string {
	return deviceID + "|" + findingKey
}

// fingerprint captures what a finding claims and the evidence behind it,
// without observation times, so a rescan with the same evidence matches.
func fingerprint(f risk.Finding) string {
	var b strings.Builder
	b.WriteString(f.Severity + "|" + f.Category + "|" + f.Confidence)
	for _, e := range f.Evidence {
		b.WriteString("|" + e.Method + ":" + e.Endpoint + ":" + e.Summary)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// ReviewFor reports the review state of finding f on device deviceID.
func (s *Store) ReviewFor(deviceID string, f risk.Finding) ReviewState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reviewFor(deviceID, f)
}

func (s *Store) reviewFor(deviceID string, f risk.Finding) ReviewState {
	r := s.inv.Reviews[reviewKey(deviceID, f.Key())]
	if r == nil {
		return ReviewState{Status: ReviewOpen}
	}
	st := ReviewState{Status: ReviewAcknowledged, Note: r.Note, At: r.At.Format("2006-01-02T15:04:05Z07:00")}
	if r.Fingerprint != fingerprint(f) {
		st.Status = ReviewReopened
	}
	return st
}

// SetReview acknowledges (ack true) or reopens a finding on a device. The
// finding is looked up in the device's latest observation, whose evidence the
// acknowledgement then covers.
func (s *Store) SetReview(deviceID, findingKey string, ack bool, note string) (ReviewState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.device(deviceID)
	if d == nil || d.Last == nil {
		return ReviewState{}, errNotFound
	}
	var f *risk.Finding
	for i := range d.Last.Findings {
		if d.Last.Findings[i].Key() == findingKey {
			f = &d.Last.Findings[i]
			break
		}
	}
	if f == nil {
		return ReviewState{}, errNotFound
	}
	k := reviewKey(deviceID, findingKey)
	if ack {
		s.inv.Reviews[k] = &Review{
			DeviceID: deviceID, Key: findingKey, Note: cleanNotes(note, 1000),
			At: now(), Fingerprint: fingerprint(*f),
		}
	} else {
		delete(s.inv.Reviews, k)
	}
	return s.reviewFor(deviceID, *f), s.persist()
}
