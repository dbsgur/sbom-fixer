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
		resp.Results = make([]osvBatchResult, len(body.Queries))
		for i, q := range body.Queries {
			if q.Package.Ecosystem == "Go" && strings.HasPrefix(q.Version, "v") {
				t.Errorf("Go version should be sent without v: %s", q.Version)
			}
			resp.Results[i].Vulns = append(resp.Results[i].Vulns, osvVulnRef{ID: "ID-" + q.Package.Name})
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

func TestOSVClient_QueryIDs_FollowsPageTokens(t *testing.T) {
	var batches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&batches, 1)
		var body struct {
			Queries []osvQuery `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		var resp osvBatchResponse
		for _, q := range body.Queries {
			var res osvBatchResult
			switch {
			case q.Package.Name == "many" && q.PageToken == "":
				res = osvBatchResult{Vulns: []osvVulnRef{{ID: "A"}}, NextPageToken: "p2"}
			case q.Package.Name == "many" && q.PageToken == "p2":
				res = osvBatchResult{Vulns: []osvVulnRef{{ID: "B"}}, NextPageToken: "p3"}
			case q.Package.Name == "many" && q.PageToken == "p3":
				res = osvBatchResult{Vulns: []osvVulnRef{{ID: "C"}}}
			case q.Package.Name == "few" && q.PageToken == "":
				res = osvBatchResult{Vulns: []osvVulnRef{{ID: "X"}}}
			default:
				t.Errorf("unexpected query %+v", q)
			}
			resp.Results = append(resp.Results, res)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	comps := []sbom.Component{
		{Name: "few", Version: "1", Ecosystem: "npm"},
		{Name: "many", Version: "1", Ecosystem: "npm"},
	}
	ids, err := newTestClient(srv).QueryIDs(context.Background(), comps)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ids[0], ","); got != "X" {
		t.Errorf("few: %s", got)
	}
	if got := strings.Join(ids[1], ","); got != "A,B,C" {
		t.Errorf("many should collect every page, got %s", got)
	}
	if batches != 3 {
		t.Errorf("only paginated queries should be re-sent: batches=%d", batches)
	}
}

func TestOSVClient_QueryIDs_StopsEndlessPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"A"}],"next_page_token":"again"}]}`))
	}))
	defer srv.Close()
	_, err := newTestClient(srv).QueryIDs(context.Background(), []sbom.Component{{Name: "a", Version: "1", Ecosystem: "npm"}})
	if err == nil {
		t.Fatal("expected error for endless pagination")
	}
}

func TestOSVClient_QueryIDs_RejectsResultCountMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
	}))
	defer srv.Close()
	comps := []sbom.Component{{Name: "a", Version: "1", Ecosystem: "npm"}, {Name: "b", Version: "1", Ecosystem: "npm"}}
	if _, err := newTestClient(srv).QueryIDs(context.Background(), comps); err == nil {
		t.Fatal("a short response must not silently drop components")
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
