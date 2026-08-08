package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

const panelAnalysisEnabledKey = "panel_strong_detection_enabled"

func (s *Server) apiPanelAnalysisSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		value, err := s.st.GetMeta(panelAnalysisEnabledKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": value == "true"})
	case http.MethodPost:
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
			return
		}
		if err := s.st.SetMeta(panelAnalysisEnabledKey, strconv.FormatBool(body.Enabled)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": body.Enabled})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (s *Server) apiPanelAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	enabled, err := s.st.GetMeta(panelAnalysisEnabledKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if enabled != "true" {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "rows": []store.PanelAnalysisRow{}, "total": 0})
		return
	}
	now := time.Now()
	q := r.URL.Query()
	startTS, _ := strconv.ParseInt(q.Get("start_ts"), 10, 64)
	endTS, _ := strconv.ParseInt(q.Get("end_ts"), 10, 64)
	if endTS <= 0 {
		endTS = now.UnixMilli()
	}
	if startTS <= 0 {
		startTS = now.Add(-7 * 24 * time.Hour).UnixMilli()
	}
	if endTS-startTS < int64(time.Minute/time.Millisecond) || endTS-startTS > int64(180*24*time.Hour/time.Millisecond) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "时间范围必须在 1 分钟到 180 天之间"})
		return
	}
	lookbackMinutes, _ := strconv.Atoi(q.Get("lookback_minutes"))
	if lookbackMinutes == 0 {
		lookbackMinutes = 20
	}
	if lookbackMinutes < 1 || lookbackMinutes > 120 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "墙前窗口必须在 1 到 120 分钟之间"})
		return
	}
	started := time.Now()
	filter := store.PanelAnalysisFilter{
		StartTS:         startTS,
		EndTS:           endTS,
		DNSName:         strings.TrimSpace(q.Get("dns_name")),
		Tenant:          strings.TrimSpace(q.Get("tenant")),
		LookbackMinutes: lookbackMinutes,
	}
	result, err := s.cachedPanelAnalysis(r.Context(), filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	classification := strings.TrimSpace(q.Get("classification"))
	search := strings.ToLower(strings.TrimSpace(q.Get("search")))
	filtered := make([]store.PanelAnalysisRow, 0, len(result.Rows))
	for _, row := range result.Rows {
		if classification != "" && classification != "all" && row.Classification != classification {
			continue
		}
		if search != "" {
			haystack := strings.ToLower(strings.Join([]string{
				row.TokenHash, row.Account, row.DNSName, row.EntryNote, row.Tenant,
				row.LastIP, row.LastUA, row.LastASN, row.LastASNOrg, row.CloudProvider,
			}, "\n"))
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		filtered = append(filtered, row)
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "summary": result.Summary, "rows": filtered[offset:end],
		"total": total, "limit": limit, "offset": offset,
		"start_ts": startTS, "end_ts": endTS, "elapsed_ms": time.Since(started).Milliseconds(),
	})
}

// cachedPanelAnalysis keeps pagination, search and classification changes from
// repeating the same multi-table aggregation. Holding panelMu while computing
// also prevents concurrent page loads from stampeding SQLite.
func (s *Server) cachedPanelAnalysis(ctx context.Context, filter store.PanelAnalysisFilter) (*store.PanelAnalysisResult, error) {
	cacheKey := fmt.Sprintf("%d\x00%d\x00%s\x00%s\x00%d", filter.StartTS, filter.EndTS, filter.DNSName, filter.Tenant, filter.LookbackMinutes)
	now := time.Now()
	s.panelMu.Lock()
	defer s.panelMu.Unlock()
	if cached, ok := s.panels[cacheKey]; ok && now.Before(cached.expires) {
		return cached.value, nil
	}
	result, err := s.st.AnalyzePanelTimeline(ctx, filter)
	if err != nil {
		return nil, err
	}
	// A short TTL is enough for interactive filtering while keeping new wall
	// evidence and subscription activity visible without a manual refresh.
	s.panels[cacheKey] = panelAnalysisCacheEntry{value: result, expires: time.Now().Add(30 * time.Second)}
	return result, nil
}
