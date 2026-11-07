package vuln

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"sbomapp/internal/sbom"
)

func newTestClient(srv *httptest.Server) *OSVClient {
	c := NewOSVClient()
	c.BaseURL = srv.URL
	c.RetryDelay = 0
	return c
}

func TestOSVClient_QueryIDs_BatchesAndStripsGoPrefix(t *testing.T) {
	var batches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		atomic.AddInt32(&batches, 1)
		var body struct {
			Queries []osvQuery `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		var resp osvBatchResponse
		resp.Results = make([]struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		}, len(body.Queries))
		for i, q := range body.Queries {
			if q.Package.Ecosystem == "Go" && strings.HasPrefix(q.Version, "v") {
				t.Errorf("Go version should be sent without v: %s", q.Version)
			}
			resp.Results[i].Vulns = append(resp.Results[i].Vulns, struct {
				ID string `json:"id"`
			}{ID: "ID-" + q.Package.Name})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cl := newTestClient(srv)
	cl.BatchSize = 2
	comps := []sbom.Component{
		{Name: "a", Version: "1", Ecosystem: "npm"},
		{Name: "b", Version: "v1.0.0", Ecosystem: "Go"},
		{Name: "c", Version: "1", Ecosystem: "PyPI"},
	}
	ids, err := cl.QueryIDs(context.Background(), comps)
	if err != nil {
		t.Fatal(err)
	}
	if batches != 2 {
		t.Errorf("want 2 batches, got %d", batches)
	}
	for i, c := range comps {
		if len(ids[i]) != 1 || ids[i][0] != "ID-"+c.Name {
			t.Errorf("ids[%d] = %v", i, ids[i])
		}
	}
}

func TestOSVClient_Advisories_CachesAndRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 { // first call fails transiently
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		_, _ = w.Write([]byte(`{"id":"` + id + `","summary":"s"}`))
	}))
	defer srv.Close()

	cl := newTestClient(srv)
	cl.Concurrency = 1
	got, err := cl.Advisories(context.Background(), []string{"X"})
	if err != nil || got["X"] == nil || got["X"].Summary != "s" {
		t.Fatalf("got %v %v", got, err)
	}
	if calls != 2 {
		t.Errorf("expected one retry, calls=%d", calls)
	}
	if _, err := cl.Advisories(context.Background(), []string{"X"}); err != nil || calls != 2 {
		t.Errorf("second lookup should be cached, calls=%d err=%v", calls, err)
	}
}

func TestOSVClient_DoesNotRetryClientErrors(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := newTestClient(srv).Advisories(context.Background(), []string{"missing"}); err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("404 should not be retried, calls=%d", calls)
	}
}
