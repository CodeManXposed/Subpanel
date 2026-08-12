package kumawatch

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func TestParseMonitorStatus(t *testing.T) {
	input := `# HELP monitor_status Monitor Status
monitor_status{monitor_id="29",monitor_name="AWS抓鬼 NEW",monitor_type="port",monitor_hostname="tra-hk1.example",monitor_port="2500"} 1
monitor_status{monitor_id="28",monitor_name="old\"name",monitor_type="port",monitor_hostname="tra-sg.example",monitor_port="2500"} 0
`
	rows, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Status != 1 || rows[1].Name != `old"name` || rows[0].Key == "" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestPollRecordsOnlyUpToDown(t *testing.T) {
	var status atomic.Int32
	status.Store(1)
	const key = "test-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "" || pass != key {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, "monitor_status{monitor_id=\"29\",monitor_name=\"AWS\",monitor_type=\"port\",monitor_hostname=\"aws.example\",monitor_port=\"2500\"} %d\n", status.Load())
	}))
	defer server.Close()

	st, err := store.Open(t.TempDir()+"/test.db", 5*time.Millisecond, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UnixMilli()
	watcher, err := st.AddDNSWatcher(ctx, store.DNSWatcher{DNSName: "aws.example", LookbackMinutes: 20, Enabled: true, LastIPs: "1.2.3.4", LastCheckedTS: now})
	if err != nil {
		t.Fatal(err)
	}
	monitors, err := (Client{}).Fetch(ctx, server.URL+"/metrics", key)
	if err != nil || len(monitors) != 1 {
		t.Fatalf("fetch: rows=%+v err=%v", monitors, err)
	}
	if err := st.UpsertKumaBinding(ctx, store.KumaMonitorBinding{WatcherID: watcher.ID, MonitorKey: monitors[0].Key,
		MonitorID: monitors[0].ID, MonitorName: monitors[0].Name, MonitorHostname: monitors[0].Hostname, MonitorPort: monitors[0].Port}); err != nil {
		t.Fatal(err)
	}
	_ = st.SetMeta(MetaURL, server.URL+"/metrics")
	_ = st.SetMeta(MetaAPIKey, key)
	_ = st.SetMeta(MetaEnabled, "true")
	mgr := &Manager{store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), client: Client{HTTP: server.Client()}}

	mgr.poll(ctx)
	got, _ := st.GetDNSWatcher(ctx, watcher.ID)
	if got.PendingFailureTS != 0 {
		t.Fatalf("baseline must not create failure: %+v", got)
	}
	status.Store(0)
	mgr.poll(ctx)
	got, _ = st.GetDNSWatcher(ctx, watcher.ID)
	if got.PendingFailureTS == 0 || got.PendingFailureIP != "1.2.3.4" {
		t.Fatalf("DOWN transition not recorded: %+v", got)
	}
	first := got.PendingFailureTS
	mgr.poll(ctx)
	got, _ = st.GetDNSWatcher(ctx, watcher.ID)
	if got.PendingFailureTS != first {
		t.Fatalf("repeated DOWN changed first failure: %d -> %d", first, got.PendingFailureTS)
	}
}
