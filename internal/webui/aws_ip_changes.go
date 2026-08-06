package webui

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/dnswatch"
	"github.com/huabanmao168/SubPanel/internal/store"
)

func (s *Server) apiAWSIPChanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	rows, err := s.st.ListAWSIPChanges(r.Context(), 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []store.AWSIPChange{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) apiAWSIPChangeAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		OccurredTS      int64  `json:"occurred_ts"`
		OldIP           string `json:"old_ip"`
		NewIP           string `json:"new_ip"`
		LookbackMinutes int    `json:"lookback_minutes"`
		Note            string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return
	}
	body.OldIP = strings.TrimSpace(body.OldIP)
	body.NewIP = strings.TrimSpace(body.NewIP)
	if net.ParseIP(body.OldIP) == nil || net.ParseIP(body.NewIP) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "old_ip and new_ip must be valid IP addresses"})
		return
	}
	if body.LookbackMinutes == 0 {
		body.LookbackMinutes = 20
	}
	if body.LookbackMinutes != 15 && body.LookbackMinutes != 20 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "lookback_minutes must be 15 or 20"})
		return
	}
	if body.OccurredTS <= 0 {
		body.OccurredTS = time.Now().UnixMilli()
	}
	change, err := s.st.AddAWSIPChange(r.Context(), store.AWSIPChange{
		OccurredTS:      body.OccurredTS,
		OldIP:           body.OldIP,
		NewIP:           body.NewIP,
		LookbackMinutes: body.LookbackMinutes,
		Note:            strings.TrimSpace(body.Note),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, change)
}

func (s *Server) apiAWSIPChangeDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid id required"})
		return
	}
	change, err := s.st.GetAWSIPChange(r.Context(), id)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	rows, err := s.st.ListAWSIPChangeSubscribers(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []store.AWSIPChangeSubscriber{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"change": change, "subscribers": rows})
}

func (s *Server) apiAWSIPChangeRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid id required"})
		return
	}
	if err := s.st.DeleteAWSIPChange(r.Context(), body.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) apiDNSWatchers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	rows, err := s.st.ListDNSWatchers(r.Context(), false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []store.DNSWatcher{}
	}
	now := time.Now().UnixMilli()
	for i := range rows {
		if rows[i].LastChangedTS > 0 && now >= rows[i].LastChangedTS {
			rows[i].AliveSeconds = (now - rows[i].LastChangedTS) / 1000
		}
		history, historyErr := s.st.ListDNSIPHistory(r.Context(), rows[i].ID, 5)
		if historyErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": historyErr.Error()})
			return
		}
		if history == nil {
			history = []store.DNSIPHistory{}
		}
		rows[i].IPHistory = history
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) apiDNSWatcherAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		DNSName         string `json:"dns_name"`
		Tenant          string `json:"tenant"`
		LookbackMinutes int    `json:"lookback_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return
	}
	body.DNSName = dnswatch.NormalizeName(body.DNSName)
	body.Tenant = strings.TrimSpace(body.Tenant)
	if body.DNSName == "" || strings.ContainsAny(body.DNSName, "/: ") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid DNS hostname required"})
		return
	}
	if body.LookbackMinutes == 0 {
		body.LookbackMinutes = 20
	}
	if body.LookbackMinutes != 15 && body.LookbackMinutes != 20 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "lookback_minutes must be 15 or 20"})
		return
	}
	if body.Tenant != "" {
		tenants, err := s.st.ListTenants()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		found := false
		for _, tenant := range tenants {
			if tenant.Name == body.Tenant {
				found = true
				break
			}
		}
		if !found {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown tenant"})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ips, err := dnswatch.ResolveIPv4(ctx, body.DNSName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "DNS resolve failed: " + err.Error()})
		return
	}
	now := time.Now().UnixMilli()
	watcher, err := s.st.AddDNSWatcher(r.Context(), store.DNSWatcher{
		DNSName: body.DNSName, Tenant: body.Tenant, LookbackMinutes: body.LookbackMinutes,
		Enabled: true, LastIPs: strings.Join(ips, ","), LastCheckedTS: now,
	})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, watcher)
}

func (s *Server) apiDNSWatcherToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		ID      int64 `json:"id"`
		Enabled bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid id required"})
		return
	}
	if err := s.st.SetDNSWatcherEnabled(r.Context(), body.ID, body.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) apiDNSWatcherNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		ID   int64  `json:"id"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid id required"})
		return
	}
	body.Note = strings.TrimSpace(body.Note)
	if len([]rune(body.Note)) > 200 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "note is too long"})
		return
	}
	if err := s.st.UpdateDNSWatcherNote(r.Context(), body.ID, body.Note); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) apiDNSWatcherRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid id required"})
		return
	}
	if err := s.st.DeleteDNSWatcher(r.Context(), body.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
