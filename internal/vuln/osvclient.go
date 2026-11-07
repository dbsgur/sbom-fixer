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
	Version string `json:"version"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// QueryIDs implements AdvisoryDB using /v1/querybatch.
func (cl *OSVClient) QueryIDs(ctx context.Context, comps []sbom.Component) ([][]string, error) {
	ids := make([][]string, len(comps))
	size := cl.BatchSize
	if size <= 0 {
		size = 500
	}
	for start := 0; start < len(comps); start += size {
		end := min(start+size, len(comps))
		queries := make([]osvQuery, 0, end-start)
		for _, c := range comps[start:end] {
			var q osvQuery
			q.Package.Name = c.Name
			q.Package.Ecosystem = c.Ecosystem
			q.Version = queryVersion(c)
			queries = append(queries, q)
		}
		var resp osvBatchResponse
		if err := cl.post(ctx, "/v1/querybatch", map[string]any{"queries": queries}, &resp); err != nil {
			return nil, err
		}
		for i, r := range resp.Results {
			if start+i >= len(ids) {
				break
			}
			for _, v := range r.Vulns {
				ids[start+i] = append(ids[start+i], v.ID)
			}
		}
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
