package webui

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/dnswatch"
	"github.com/huabanmao168/SubPanel/internal/store"
)

// apiAWSFailureReport 接收 AWS 自动换 IP 脚本的大陆 TCP 首次失联信号。
// 该时间只作为后续 DNS 变化快照的精准锚点，不会单独制造换 IP 记录。
func (s *Server) apiAWSFailureReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	secret, _ := s.st.GetMeta("report_secret")
	if secret == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "report secret is not configured"})
		return
	}
	if !hmac.Equal([]byte(r.Header.Get("X-Report-Key")), []byte(secret)) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "invalid report key"})
		return
	}
	var body struct {
		DNSName  string `json:"dns_name"`
		Tenant   string `json:"tenant"`
		IP       string `json:"ip"`
		FailedTS int64  `json:"failed_ts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return
	}
	body.DNSName = dnswatch.NormalizeName(body.DNSName)
	body.Tenant = strings.TrimSpace(body.Tenant)
	body.IP = strings.TrimSpace(body.IP)
	if body.DNSName == "" || net.ParseIP(body.IP) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid dns_name and ip required"})
		return
	}
	now := time.Now().UnixMilli()
	if body.FailedTS <= 0 {
		body.FailedTS = now
	}
	if body.FailedTS > now+int64(5*time.Minute/time.Millisecond) || body.FailedTS < now-int64(2*time.Hour/time.Millisecond) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed_ts must be within the last 2 hours"})
		return
	}
	watcher, err := s.st.MarkDNSWatcherFailure(r.Context(), body.DNSName, body.Tenant, body.IP, body.FailedTS)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "active DNS watcher not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "watcher_id": watcher.ID, "failure_ts": watcher.PendingFailureTS,
		"message": "failure anchor recorded; waiting for DNS change",
	})
}

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

// apiAWSSuspects 汇总最近最多 50 次 AWS 换 IP 快照中的入口/站点/Token 关联。
func (s *Server) apiAWSSuspects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	rows, err := s.st.ListAWSSuspectSummaries(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.annotateAWSSuspectWhitelist(rows)
	q := r.URL.Query()
	dnsName := strings.TrimSpace(q.Get("dns_name"))
	tenant := strings.TrimSpace(q.Get("tenant"))
	token := strings.TrimSpace(q.Get("token"))
	includeDetails := q.Get("details") == "1"
	out := make([]store.AWSSuspectSummary, 0, len(rows))
	for i := range rows {
		if dnsName != "" && rows[i].DNSName != dnsName {
			continue
		}
		if tenant != "" && rows[i].Tenant != tenant {
			continue
		}
		if token != "" && rows[i].TokenHash != token {
			continue
		}
		for _, ua := range rows[i].UAs {
			if !blacklist.IsKnownSubClient(ua) {
				rows[i].HasUncommonUA = true
				break
			}
		}
		if !includeDetails {
			rows[i].Occurrences = nil
		}
		out = append(out, rows[i])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) annotateAWSSuspectWhitelist(rows []store.AWSSuspectSummary) {
	if s.rules == nil {
		return
	}
	for i := range rows {
		for j := range rows[i].IPs {
			rows[i].IPs[j].Whitelisted = s.rules.IPWhitelisted(rows[i].IPs[j].IP)
		}
	}
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
	if body.LookbackMinutes < 1 || body.LookbackMinutes > 120 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "lookback_minutes must be between 1 and 120"})
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
	history, err := s.st.AWSIPChangeTokenHistory(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	for i := range rows {
		rows[i].UAUncommon = !blacklist.IsKnownSubClient(rows[i].UA)
		anchor := change.FailureTS
		if anchor <= 0 {
			anchor = change.OccurredTS
		}
		if rows[i].LastSeenTS <= anchor {
			rows[i].SecondsBeforeFailure = (anchor - rows[i].LastSeenTS) / 1000
		}
		if h, ok := history[rows[i].Tenant+"\x00"+rows[i].TokenHash]; ok {
			rows[i].RecentChangeHits = h.Hits
			rows[i].RecentChangeTotal = h.Total
			rows[i].RepeatedBeforeChanges = h.Hits >= 2
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Tenant != rows[j].Tenant {
			return rows[i].Tenant < rows[j].Tenant
		}
		if rows[i].RecentChangeHits != rows[j].RecentChangeHits {
			return rows[i].RecentChangeHits > rows[j].RecentChangeHits
		}
		if rows[i].SecondsBeforeFailure != rows[j].SecondsBeforeFailure {
			return rows[i].SecondsBeforeFailure < rows[j].SecondsBeforeFailure
		}
		return rows[i].LastSeenTS > rows[j].LastSeenTS
	})
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
	if body.LookbackMinutes < 1 || body.LookbackMinutes > 120 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "lookback_minutes must be between 1 and 120"})
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

func (s *Server) apiDNSWatcherLookback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		ID      int64 `json:"id"`
		Minutes int   `json:"minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "valid id required"})
		return
	}
	if body.Minutes < 1 || body.Minutes > 120 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "minutes must be between 1 and 120"})
		return
	}
	if err := s.st.UpdateDNSWatcherLookback(r.Context(), body.ID, body.Minutes); err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "watcher not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "minutes": body.Minutes})
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
