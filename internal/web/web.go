// Package web serves the management UI and its JSON API.
package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/okmtdev/local-dns/internal/store"
)

//go:embed static
var staticFS embed.FS

// ScannerControl is what the UI needs from the scanner.
type ScannerControl interface {
	Trigger()
	LastScan() time.Time
}

// Info is static server information shown in the UI.
type Info struct {
	Version      string
	Domain       string
	DNSListen    string
	TTL          uint32
	ScanInterval time.Duration
	Upstreams    []string
}

// Server is the HTTP handler factory.
type Server struct {
	Store    *store.Store
	Scanner  ScannerControl
	Info     Info
	Username string
	Password string
	Log      *slog.Logger
}

// Handler builds the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/status", s.getStatus)
	mux.HandleFunc("GET /api/devices", s.getDevices)
	mux.HandleFunc("PATCH /api/devices/{mac}", s.patchDevice)
	mux.HandleFunc("DELETE /api/devices/{mac}", s.deleteDevice)
	mux.HandleFunc("GET /api/mappings", s.getMappings)
	mux.HandleFunc("POST /api/mappings", s.postMapping)
	mux.HandleFunc("PUT /api/mappings/{hostname}", s.putMapping)
	mux.HandleFunc("DELETE /api/mappings/{hostname}", s.deleteMapping)
	mux.HandleFunc("POST /api/scan", s.postScan)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	index, err := fs.ReadFile(static, "index.html")
	if err != nil {
		panic(err)
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(index)
	})

	return s.withAuth(withSecurityHeaders(mux))
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.Username == "" {
		return next
	}
	wantUser := sha256.Sum256([]byte(s.Username))
	wantPass := sha256.Sum256([]byte(s.Password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok {
			gotUser := sha256.Sum256([]byte(user))
			gotPass := sha256.Sum256([]byte(pass))
			userOK := subtle.ConstantTimeCompare(gotUser[:], wantUser[:]) == 1
			passOK := subtle.ConstantTimeCompare(gotPass[:], wantPass[:]) == 1
			if userOK && passOK {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="local-dns"`)
		http.Error(w, "認証が必要です", http.StatusUnauthorized)
	})
}

// ---- DTOs ----

type deviceDTO struct {
	MAC         string    `json:"mac"`
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
	Vendor      string    `json:"vendor"`
	Label       string    `json:"label"`
	DisplayName string    `json:"display_name"`
	Self        bool      `json:"self"`
	Online      bool      `json:"online"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Names       []nameDTO `json:"names"`
}

type nameDTO struct {
	Hostname string `json:"hostname"`
	FQDN     string `json:"fqdn"`
}

type mappingDTO struct {
	Hostname   string    `json:"hostname"`
	FQDN       string    `json:"fqdn"`
	MAC        string    `json:"mac"`
	IP         string    `json:"ip"`
	Static     bool      `json:"static"`
	Note       string    `json:"note"`
	CurrentIP  string    `json:"current_ip"`
	DeviceName string    `json:"device_name"`
	Online     bool      `json:"online"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type statusDTO struct {
	Version         string     `json:"version"`
	Domain          string     `json:"domain"`
	DNSListen       string     `json:"dns_listen"`
	TTL             uint32     `json:"ttl"`
	ScanIntervalSec int        `json:"scan_interval_sec"`
	Upstreams       []string   `json:"upstreams"`
	LastScan        *time.Time `json:"last_scan"`
	DeviceCount     int        `json:"device_count"`
	OnlineCount     int        `json:"online_count"`
	Now             time.Time  `json:"now"`
}

// ---- handlers ----

func (s *Server) getStatus(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	total, online := s.Store.Counts(now)
	dto := statusDTO{
		Version:         s.Info.Version,
		Domain:          s.Info.Domain,
		DNSListen:       s.Info.DNSListen,
		TTL:             s.Info.TTL,
		ScanIntervalSec: int(s.Info.ScanInterval / time.Second),
		Upstreams:       s.Info.Upstreams,
		DeviceCount:     total,
		OnlineCount:     online,
		Now:             now,
	}
	if t := s.Scanner.LastScan(); !t.IsZero() {
		dto.LastScan = &t
	}
	writeJSON(w, http.StatusOK, dto)
}

func (s *Server) getDevices(w http.ResponseWriter, _ *http.Request) {
	views := s.Store.Devices(time.Now())
	out := make([]deviceDTO, 0, len(views))
	for _, v := range views {
		dto := deviceDTO{
			MAC:         v.MAC,
			IP:          v.IP,
			Hostname:    v.Hostname,
			Vendor:      v.Vendor,
			Label:       v.Label,
			DisplayName: displayName(v),
			Self:        v.Self,
			Online:      v.Online,
			FirstSeen:   v.FirstSeen,
			LastSeen:    v.LastSeen,
			Names:       make([]nameDTO, 0, len(v.Names)),
		}
		for _, n := range v.Names {
			dto.Names = append(dto.Names, nameDTO{Hostname: n, FQDN: n + "." + s.Info.Domain})
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, out)
}

func displayName(v store.DeviceView) string {
	switch {
	case v.Label != "":
		return v.Label
	case v.Hostname != "":
		return v.Hostname
	default:
		return v.MAC
	}
}

func (s *Server) patchDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label *string `json:"label"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Label == nil {
		writeError(w, http.StatusBadRequest, errors.New("label フィールドが必要です"))
		return
	}
	if err := s.Store.SetLabel(r.PathValue("mac"), *body.Label); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteDevice(r.PathValue("mac")); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) getMappings(w http.ResponseWriter, _ *http.Request) {
	views := s.Store.Mappings(time.Now())
	out := make([]mappingDTO, 0, len(views))
	for _, v := range views {
		out = append(out, mappingDTO{
			Hostname:   v.Hostname,
			FQDN:       v.Hostname + "." + s.Info.Domain,
			MAC:        v.MAC,
			IP:         v.IP,
			Static:     v.IP != "",
			Note:       v.Note,
			CurrentIP:  v.CurrentIP,
			DeviceName: v.DeviceName,
			Online:     v.Online,
			UpdatedAt:  v.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) postMapping(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hostname string `json:"hostname"`
		MAC      string `json:"mac"`
		IP       string `json:"ip"`
		Note     string `json:"note"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	m, err := s.Store.SetMapping(body.Hostname, strings.TrimSpace(body.MAC), strings.TrimSpace(body.IP), body.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("mapping saved", "hostname", m.Hostname, "mac", m.MAC, "ip", m.IP)
	writeJSON(w, http.StatusOK, m)
}

// putMapping updates an existing mapping; the body may carry a new
// hostname (rename), a new target, and a new note.
func (s *Server) putMapping(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hostname string `json:"hostname"`
		MAC      string `json:"mac"`
		IP       string `json:"ip"`
		Note     string `json:"note"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	old := r.PathValue("hostname")
	m, err := s.Store.UpdateMapping(old, body.Hostname, strings.TrimSpace(body.MAC), strings.TrimSpace(body.IP), body.Note)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, store.ErrMappingNotFound) {
			code = http.StatusNotFound
		}
		writeError(w, code, err)
		return
	}
	s.Log.Info("mapping updated", "from", old, "hostname", m.Hostname, "mac", m.MAC, "ip", m.IP)
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) deleteMapping(w http.ResponseWriter, r *http.Request) {
	hostname := r.PathValue("hostname")
	existed, err := s.Store.DeleteMapping(hostname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !existed {
		writeError(w, http.StatusNotFound, errors.New("マッピングが見つかりません"))
		return
	}
	s.Log.Info("mapping deleted", "hostname", hostname)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) postScan(w http.ResponseWriter, _ *http.Request) {
	s.Scanner.Trigger()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "scanning"})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("リクエストボディのJSONが不正です")
	}
	return nil
}
