package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"sort"

	"github.com/BVisagie/network-sweeper/internal/inventory"
	"github.com/BVisagie/network-sweeper/internal/risk"
)

const maxBody = 64 << 10

// findingView is a finding with its review state on the device.
type findingView struct {
	risk.Finding
	DeviceID string                `json:"deviceId"`
	Review   inventory.ReviewState `json:"review"`
}

// deviceView is a device as the dashboard shows it.
type deviceView struct {
	inventory.Device
	Findings []findingView `json:"findings"`
	// SeenInLatest is true when the profile's newest scan observed the device.
	SeenInLatest bool `json:"seenInLatest"`
	// New is true when the newest scan is the first to observe it.
	New bool `json:"new"`
	// InLatestScope is true when the newest scan's ranges covered the device's
	// last address, so its absence from that scan means something.
	InLatestScope bool `json:"inLatestScope"`
}

func (s *Server) view(d inventory.Device, latest *inventory.ScanEntry, detail bool) deviceView {
	v := deviceView{Device: d, Findings: []findingView{}}
	if latest != nil {
		v.SeenInLatest = d.LastScanID == latest.ID
		v.New = v.SeenInLatest && d.FirstSeen.Equal(latest.FinishedAt)
		ip := net.ParseIP(lastIP(d))
		for _, r := range latest.Ranges {
			if _, n, err := net.ParseCIDR(r); err == nil && ip != nil && n.Contains(ip) {
				v.InLatestScope = true
				break
			}
		}
	}
	if d.Last != nil {
		for _, f := range d.Last.Findings {
			v.Findings = append(v.Findings, findingView{Finding: f, DeviceID: d.ID, Review: s.Store.ReviewFor(d.ID, f)})
		}
	}
	if !detail {
		v.History = nil
	}
	return v
}

func (s *Server) latestScan(profileID string) *inventory.ScanEntry {
	scans := s.Store.Scans(profileID)
	if len(scans) == 0 {
		return nil
	}
	return &scans[0]
}

// profileParam picks the requested profile, else the most recent one.
func (s *Server) profileParam(r *http.Request) string {
	if p := r.URL.Query().Get("profile"); p != "" {
		return p
	}
	return s.Store.CurrentProfile()
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	profileID := s.profileParam(r)
	latest := s.latestScan(profileID)
	devices := s.Store.Devices(profileID)
	views := make([]deviceView, 0, len(devices))
	for _, d := range devices {
		views = append(views, s.view(d, latest, false))
	}
	sort.SliceStable(views, func(i, j int) bool { return ipLess(lastIP(views[i].Device), lastIP(views[j].Device)) })
	writeJSON(w, map[string]any{
		"storage":    s.Store.Status(),
		"retention":  s.Store.Retention(),
		"profiles":   s.Store.Profiles(),
		"profileId":  profileID,
		"latestScan": latest,
		"devices":    views,
	})
}

func ipLess(a, b string) bool {
	ai, bi := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ai == nil || bi == nil {
		return a < b
	}
	return bytes.Compare(ai, bi) < 0
}

func lastIP(d inventory.Device) string {
	if d.Last != nil {
		return d.Last.Host.IP
	}
	return d.Address
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.Store.Device(r.PathValue("id"))
	if !ok {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	writeJSON(w, s.view(d, s.latestScan(d.ProfileID), true))
}

func (s *Server) handleAnnotate(w http.ResponseWriter, r *http.Request) {
	var a inventory.Annotation
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&a); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	d, err := s.Store.Annotate(r.PathValue("id"), a)
	if inventory.IsNotFound(err) {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	out := map[string]any{"device": s.view(d, s.latestScan(d.ProfileID), true)}
	if err != nil {
		out["saveError"] = err.Error()
	}
	writeJSON(w, out)
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key          string `json:"key"`
		Acknowledged bool   `json:"acknowledged"`
		Note         string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	st, err := s.Store.SetReview(r.PathValue("id"), req.Key, req.Acknowledged, req.Note)
	if inventory.IsNotFound(err) {
		http.Error(w, "finding not found on this device's latest observation", http.StatusNotFound)
		return
	}
	out := map[string]any{"review": st}
	if err != nil {
		out["saveError"] = err.Error()
	}
	writeJSON(w, out)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	scans := s.Store.Scans(s.profileParam(r))
	if scans == nil {
		scans = []inventory.ScanEntry{}
	}
	writeJSON(w, map[string]any{"scans": scans})
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := s.Store.Compare(s.profileParam(r), q.Get("current"), q.Get("previous"))
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, c)
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	err := s.Store.RenameProfile(r.PathValue("id"), req.Name)
	if inventory.IsNotFound(err) {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}
	out := map[string]any{"profiles": s.Store.Profiles()}
	if err != nil {
		out["saveError"] = err.Error()
	}
	writeJSON(w, out)
}

func (s *Server) handleDeleteHistory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		What string `json:"what"` // "scans" keeps devices and notes; "all" removes everything
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	var err error
	switch req.What {
	case "scans":
		err = s.Store.DeleteHistory()
	case "all":
		err = s.Store.DeleteAll()
	default:
		http.Error(w, `what must be "scans" or "all"`, http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"status": "deleted"})
}
