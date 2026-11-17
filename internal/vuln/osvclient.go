package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"sbomapp/internal/sbom"
)

// OSVClient is an AdvisoryDB backed by the OSV.dev REST API.
type OSVClient struct {
	BaseURL     string
	HTTP        *http.Client
	BatchSize   int
	Concurrency int
	RetryDelay  time.Duration

	mu    sync.Mutex
	cache map[string]*Advisory
}

var _ AdvisoryDB = (*OSVClient)(nil)

func NewOSVClient() *OSVClient {
	return &OSVClient{
		BaseURL:     "https://api.osv.dev",
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		BatchSize:   500,
		Concurrency: 8,
		RetryDelay:  500 * time.Millisecond,
		cache:       map[string]*Advisory{},
	}
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type osvVulnRef struct {
	ID string `json:"id"`
}

type osvBatchResult struct {
	Vulns []osvVulnRef `json:"vulns"`
	// NextPageToken is set when OSV truncated this query's results; the
	// same query must be sent again with page_token to get the rest.
	NextPageToken string `json:"next_page_token"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

// maxQueryPages bounds how often a single query is re-sent for more pages,
// so a misbehaving server cannot keep the scan looping forever.
const maxQueryPages = 50

// QueryIDs implements AdvisoryDB using /v1/querybatch. Queries whose
// results were paginated are re-sent with their page token until every page
// has been read, so packages with many advisories are not cut short.
func (cl *OSVClient) QueryIDs(ctx context.Context, comps []sbom.Component) ([][]string, error) {
	ids := make([][]string, len(comps))
	size := cl.BatchSize
	if size <= 0 {
		size = 500
	}
	queries := make([]osvQuery, len(comps))
	pending := make([]int, len(comps))
	for i, c := range comps {
		queries[i].Package.Name = c.Name
		queries[i].Package.Ecosystem = c.Ecosystem
		queries[i].Version = queryVersion(c)
		pending[i] = i
	}
	for page := 0; len(pending) > 0; page++ {
		if page >= maxQueryPages {
			return nil, fmt.Errorf("OSV 결과 페이지가 너무 많습니다 (%d페이지 초과)", maxQueryPages)
		}
		var next []int
		for start := 0; start < len(pending); start += size {
			chunk := pending[start:min(start+size, len(pending))]
			batch := make([]osvQuery, len(chunk))
			for k, i := range chunk {
				batch[k] = queries[i]
			}
			var resp osvBatchResponse
			if err := cl.post(ctx, "/v1/querybatch", map[string]any{"queries": batch}, &resp); err != nil {
				return nil, err
			}
			if len(resp.Results) != len(chunk) {
				return nil, fmt.Errorf("OSV 응답 개수가 요청과 다릅니다 (요청 %d, 응답 %d)", len(chunk), len(resp.Results))
			}
			for k, r := range resp.Results {
				i := chunk[k]
				for _, v := range r.Vulns {
					ids[i] = append(ids[i], v.ID)
				}
				if r.NextPageToken != "" {
					queries[i].PageToken = r.NextPageToken
					next = append(next, i)
				}
			}
		}
		pending = next
	}
	return ids, nil
}

// Advisories implements AdvisoryDB using /v1/vulns/{id}, in parallel and
// cached for the lifetime of the client.
func (cl *OSVClient) Advisories(ctx context.Context, ids []string) (map[string]*Advisory, error) {
	conc := cl.Concurrency
	if conc <= 0 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	for _, id := range ids {
		if cl.cached(id) != nil {
			continue
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var a Advisory
			if err := cl.get(ctx, "/v1/vulns/"+id, &a); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("취약점 %s 조회 실패: %w", id, err)
				}
				errMu.Unlock()
				return
			}
			cl.mu.Lock()
			cl.cache[id] = &a
			cl.mu.Unlock()
		}(id)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	out := make(map[string]*Advisory, len(ids))
	for _, id := range ids {
		out[id] = cl.cached(id)
	}
	return out, nil
}

func (cl *OSVClient) cached(id string) *Advisory {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.cache == nil {
		cl.cache = map[string]*Advisory{}
	}
	return cl.cache[id]
}

func (cl *OSVClient) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return cl.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cl.BaseURL+path, bytes.NewReader(b))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, err
	}, out)
}

func (cl *OSVClient) get(ctx context.Context, path string, out any) error {
	return cl.do(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, cl.BaseURL+path, nil)
	}, out)
}

// do sends a request, retrying on network errors, 429 and 5xx.
func (cl *OSVClient) do(ctx context.Context, newReq func() (*http.Request, error), out any) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * cl.RetryDelay):
			}
		}
		req, err := newReq()
		if err != nil {
			return err
		}
		resp, err := cl.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		retry, err := decode(resp, out)
		if !retry {
			return err
		}
		lastErr = err
	}
	return lastErr
}

func decode(resp *http.Response, out any) (retry bool, err error) {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return retryable, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return false, json.NewDecoder(resp.Body).Decode(out)
}
