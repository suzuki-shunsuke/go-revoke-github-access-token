// Package revoke calls GitHub's credential revocation API to revoke leaked
// GitHub credentials (e.g. GitHub App User Access Tokens or Personal Access
// Tokens). The endpoint is unauthenticated -- authenticated requests are
// rejected with 403 -- and accepts up to 1000 credentials per request.
//
// The endpoint is rate limited to 60 unauthenticated requests per hour, so at
// most 60 batches (60,000 credentials) can be revoked per hour. When the limit
// is exceeded GitHub responds with 429 and Revoke reports a *RateLimitError.
//
// https://docs.github.com/en/rest/credentials/revoke
package revoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	// revokeURL is GitHub's unauthenticated credential revocation endpoint.
	revokeURL = "https://api.github.com/credentials/revoke"
	// apiVersion is the X-GitHub-Api-Version sent with the request.
	apiVersion = "2026-03-10"
	// maxCredentialsPerRequest is the maximum number of credentials GitHub
	// accepts in a single revocation request.
	maxCredentialsPerRequest = 1000
)

// RateLimitError is returned when GitHub rejects a revocation request with
// 429 Too Many Requests. The credential revocation endpoint allows only 60
// unauthenticated requests per hour. Callers can inspect RetryAfter to decide
// whether and when to retry, typically via errors.As:
//
//	var rle *revoke.RateLimitError
//	if errors.As(err, &rle) {
//		time.Sleep(rle.RetryAfter)
//		// retry the failed batch
//	}
type RateLimitError struct {
	// RetryAfter is the wait suggested by the Retry-After response header. It is
	// 0 when the header is absent, unparsable, or already in the past.
	RetryAfter time.Duration
	// Body is the response body returned by GitHub.
	Body string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("revoke credentials: rate limited by GitHub (retry_after=%s body=%s)", e.RetryAfter, e.Body)
}

// Client revokes GitHub credentials through the credential revocation API.
type Client struct {
	httpClient *http.Client
}

// New creates a revoke client. When c is nil, http.DefaultClient is used.
// Tests can inject a fake by passing an *http.Client with a custom Transport.
func New(c *http.Client) *Client {
	if c == nil {
		c = http.DefaultClient
	}
	return &Client{httpClient: c}
}

// Revoke revokes the given credentials. It splits them into batches of at most
// maxCredentialsPerRequest and sends them sequentially. It is a no-op when
// tokens is empty.
//
// GitHub rate limits the endpoint to 60 requests per hour; if a batch is rate
// limited the returned error wraps a *RateLimitError (retrievable with
// errors.As). Revoke does not retry on its own. Remaining batches are still
// attempted, and all batch errors are joined into the returned error.
func (c *Client) Revoke(ctx context.Context, tokens []string) error {
	var errs []error
	for start := 0; start < len(tokens); start += maxCredentialsPerRequest {
		end := min(start+maxCredentialsPerRequest, len(tokens))
		if err := c.revoke(ctx, tokens[start:end]); err != nil {
			errs = append(errs, fmt.Errorf("revoke a batch of credentials [%d:%d]: %w", start, end, err))
		}
	}
	return errors.Join(errs...)
}

// revoke sends a single revocation request for up to maxCredentialsPerRequest tokens.
func (c *Client) revoke(ctx context.Context, tokens []string) error {
	body, err := json.Marshal(map[string][]string{"credentials": tokens})
	if err != nil {
		return fmt.Errorf("marshal a request body as JSON: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revokeURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create a request to revoke credentials: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send a request to revoke credentials: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// A successful revocation returns 202 Accepted.
	if resp.StatusCode == http.StatusTooManyRequests {
		b, _ := io.ReadAll(resp.Body)
		return &RateLimitError{
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
			Body:       string(b),
		}
	}
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke credentials (status_code=%d body=%s)", resp.StatusCode, string(b))
	}
	// Drain the body so the HTTP connection can be reused across batches.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// parseRetryAfter interprets a Retry-After header value, which is either a
// number of seconds or an HTTP date. It returns 0 when the value is empty,
// unparsable, or already in the past.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
