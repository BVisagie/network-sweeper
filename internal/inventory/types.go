// Package inventory keeps scan history, device identity, annotations, and
// finding review state, on disk or in memory only.
package inventory

import (
	"time"

	"github.com/BVisagie/network-sweeper/internal/discover"
	"github.com/BVisagie/network-sweeper/internal/risk"
	"github.com/BVisagie/network-sweeper/internal/scan"
)

// SchemaVersion is the storage format this build reads and writes. Files with
// a higher version are left untouched.
const SchemaVersion = 1

// DefaultRetention is how many scans are kept unless the user changes it.
const DefaultRetention = 100

// Coverage is what a scan set out to cover.
type Coverage struct {
	Ranges    []string `json:"ranges"`
	Skipped   []string `json:"skipped,omitempty"` // local subnets too large to include by default
	Addresses int      `json:"addresses"`
	Limit     int      `json:"limit"`
	Methods   []string `json:"methods"`
	Deep      bool     `json:"deep"`
	Custom    bool     `json:"customRange"`
}

// Snapshot is one finished scan. Canceled and timed-out scans keep what they
// observed and are flagged Partial.
type Snapshot struct {
	Version     int             `json:"version,omitempty"`
	ID          string          `json:"id"`
	State       string          `json:"state"`
	Partial     bool            `json:"partial"`
	Coverage    Coverage        `json:"coverage"`
	ProfileID   string          `json:"profileId,omitempty"`
	StartedAt   time.Time       `json:"startedAt"`
	FinishedAt  time.Time       `json:"finishedAt"`
	DurationMs  int64           `json:"durationMs"`
	Targets     []string        `json:"targets"`
	Deep        bool            `json:"deep"`
	CustomRange bool            `json:"customRange"`
	Hosts       []discover.Host `json:"hosts"`
	Ports       []scan.Result   `json:"ports"`
	Findings    []risk.Finding  `json:"findings"`
	GatewayIP   string          `json:"gatewayIp,omitempty"`
	GatewayMAC  string          `json:"gatewayMac,omitempty"`
	// GatewaySubnet is the local subnet holding the gateway: with GatewayMAC it
	// identifies the network the scan ran from.
	GatewaySubnet string `json:"gatewaySubnet,omitempty"`
	Error         string `json:"error,omitempty"`
	Warning       string `json:"warning"`
}

// Profile is a network the app has scanned from, keyed on the gateway's MAC
// plus its subnet. Two networks that both use 192.168.1.0/24 stay separate.
type Profile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	GatewayMAC string `json:"gatewayMac,omitempty"`
	Subnet     string `json:"subnet"`
	// Verified is false when the gateway MAC was unknown and the profile falls
	// back to the subnet alone.
	Verified bool      `json:"verified"`
	Created  time.Time `json:"created"`
	LastScan time.Time `json:"lastScan"`
}

// Identity bases.
const (
	BasisMAC     = "mac"     // matched on MAC within the profile
	BasisAddress = "address" // no usable MAC; tracked by IP address only
)

// Device is one thing on a network, with the user's annotations and its
// latest observation.
type Device struct {
	ID        string `json:"id"`
	ProfileID string `json:"profileId"`
	Basis     string `json:"basis"`
	MAC       string `json:"mac,omitempty"`
	Address   string `json:"address,omitempty"` // key for BasisAddress devices

	Name  string   `json:"name,omitempty"`
	Notes string   `json:"notes,omitempty"`
	Tags  []string `json:"tags,omitempty"`

	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	LastScanID string    `json:"lastScanId"`
	// Uncertain explains why this identity may be wrong (private MAC, shared
	// MAC, duplicate IP), from the latest observation.
	Uncertain []string       `json:"uncertain,omitempty"`
	Last      *Observation   `json:"last,omitempty"`
	Addresses []AddressSeen  `json:"addresses,omitempty"`
	History   []HistoryEntry `json:"history,omitempty"`
}

// Observation is what one scan saw of a device.
type Observation struct {
	ScanID   string          `json:"scanId"`
	At       time.Time       `json:"at"`
	Partial  bool            `json:"partial"`
	Host     discover.Host   `json:"host"`
	Ports    []scan.OpenPort `json:"ports"`
	Closed   []int           `json:"closed,omitempty"`
	Findings []risk.Finding  `json:"findings"`
}

// AddressSeen records when a device held an address.
type AddressSeen struct {
	IP    string    `json:"ip"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// HistoryEntry summarizes a device in one retained scan.
type HistoryEntry struct {
	ScanID   string    `json:"scanId"`
	At       time.Time `json:"at"`
	IP       string    `json:"ip"`
	Ports    []int     `json:"ports,omitempty"`
	Findings int       `json:"findings"`
	Partial  bool      `json:"partial,omitempty"`
}

// ScanEntry indexes one retained snapshot.
type ScanEntry struct {
	ID         string    `json:"id"`
	ProfileID  string    `json:"profileId"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	State      string    `json:"state"`
	Partial    bool      `json:"partial"`
	Ranges     []string  `json:"ranges"`
	Methods    []string  `json:"methods"`
	Hosts      int       `json:"hosts"`
	Findings   int       `json:"findings"`
}

// Review is the user's acknowledgement of a finding on a device. Fingerprint
// captures the evidence at the time; when it changes the review reopens.
type Review struct {
	DeviceID    string    `json:"deviceId"`
	Key         string    `json:"key"`
	Note        string    `json:"note,omitempty"`
	At          time.Time `json:"at"`
	Fingerprint string    `json:"fingerprint"`
}

// Review states reported with findings.
const (
	ReviewOpen         = "open"
	ReviewAcknowledged = "acknowledged"
	ReviewReopened     = "reopened" // acknowledged, but the evidence has changed since
)

// inventoryFile is the metadata index, replaced atomically on every change.
type inventoryFile struct {
	Version       int                `json:"version"`
	Retention     int                `json:"retention"`
	LastProfileID string             `json:"lastProfileId,omitempty"`
	Profiles      []*Profile         `json:"profiles"`
	Devices       []*Device          `json:"devices"`
	Reviews       map[string]*Review `json:"reviews"`
	Scans         []ScanEntry        `json:"scans"`
}
