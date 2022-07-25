package ocm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	proofOutOfBandPath    = "/proof/v1/out-of-band-proof"
	proofPresentationPath = "/proof/v1/find-by-presentation-id"
)

// Client is the OCM service client
type Client struct {
	addr       string
	httpClient *http.Client
}

// New initializes an OCM service client given the OCM service address
func New(addr string, opts ...Option) *Client {
	c := &Client{
		addr:       addr,
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetLoginProofInvitation calls the "invitation" endpoint on
// the "out-of-band" protocol in the OCM.
func (c *Client) GetLoginProofInvitation(ctx context.Context, credTypes []string) (*LoginProofInvitationResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.addr+proofOutOfBandPath, nil)
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Add("type", strings.Join(credTypes, ","))
	req.URL.RawQuery = v.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint:errcheck

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code: %s", resp.Status)
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response LoginProofInvitationResponse
	if err := json.Unmarshal(bytes, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// GetLoginProofResult calls the "find-by-presentation-id" endpoint in the OCM.
func (c *Client) GetLoginProofResult(ctx context.Context, presentationID string) (*LoginProofResultResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.addr+proofPresentationPath, nil)
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Add("presentationId", presentationID)
	req.URL.RawQuery = v.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code: %s", resp.Status)
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response LoginProofResultResponse
	if err := json.Unmarshal(bytes, &response); err != nil {
		return nil, err
	}

	return &response, nil
}
