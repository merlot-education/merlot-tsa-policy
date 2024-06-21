package ocm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	proofOutOfBandPath        = "/v1/out-of-band-proof"
	proofOutOfBandRequestPath = "/v1/send-out-of-band-presentation-request"
	proofPresentationPath     = "/v1/find-by-presentation-id"
)

// Client is the OCM service client
type Client struct {
	proofManagerAddr string
	httpClient       *http.Client
}

type AgentDidsResponse struct {
	AgentDids []string `json:"agentDids"`
}

// New initializes an OCM service client given the OCM service address
func New(proofManagerAddr string, opts ...Option) *Client {
	c := &Client{
		proofManagerAddr: proofManagerAddr,
		httpClient:       http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetLoginProofInvitation calls the "invitation" endpoint on
// the "out-of-band" protocol in the OCM.
func (c *Client) GetLoginProofInvitation(ctx context.Context, credTypes []string) (*LoginProofInvitationResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.proofManagerAddr+proofOutOfBandPath, nil)
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

// SendOutOfBandRequest calls the "send out of band presentation request" endpoint on
// the "out-of-band" protocol in the OCM.
func (c *Client) SendOutOfBandRequest(ctx context.Context, r map[string]interface{}) (*LoginProofInvitationResponse, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.proofManagerAddr+proofOutOfBandRequestPath, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

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
	resBytes, err := c.findByPresentationID(ctx, presentationID)
	if err != nil {
		return nil, err
	}

	var response LoginProofResultResponse
	if err := json.Unmarshal(resBytes, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// GetRawLoginProofResult calls the "find-by-presentation-id" endpoint in the OCM and returns the raw result.
func (c *Client) GetRawLoginProofResult(ctx context.Context, presentationID string) (map[string]interface{}, error) {
	resBytes, err := c.findByPresentationID(ctx, presentationID)
	if err != nil {
		return nil, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(resBytes, &response); err != nil {
		return nil, err
	}

	return response, nil
}

func (c *Client) findByPresentationID(ctx context.Context, presentationID string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.proofManagerAddr+proofPresentationPath, nil)
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Add("proofRecordId", presentationID)
	req.URL.RawQuery = v.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response code: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

// The re
func (c *Client) GetWhitelistingQuery(ctx context.Context, presentationID string) (bool, error) {
	fmt.Println("Enters Whitelisting Check")
	resBytes, err := c.findByPresentationID(ctx, presentationID)
	if err != nil {
		return false, err
	}

	var response LoginProofResultResponse
	if err := json.Unmarshal(resBytes, &response); err != nil {
		return false, err
	}

	//the easiest way to get the issuer did from the presentation seems through the creddef
	creddef := response.Data.Presentations[0].CredDefID
	endOfDid := strings.Index(creddef, ":")
	did := creddef[0:endOfDid]

	var allowed AgentDidsResponse
	var issuer string
	claims := map[string]interface{}{}

	//The extracted did above (from the agent) will be checked against the did from inside the claims
	for _, pres := range response.Data.Presentations {
		for cName, cValue := range pres.Claims {
			claims[cName] = cValue
			if cName == "issuerDID" {
				issuer = claims["issuerDID"].(string)
			}
		}
	}
	//this calls the MPO to retrieve a list of allowed issueres according to the MPO based on the given didweb
	allowed, _ = getAllowedDids(issuer)

	//check whitelisting
	for _, v := range allowed.AgentDids {
		if v == did {
			fmt.Println("Is in whitelist. Value:", v)
			return true, nil
		}
	}

	fmt.Println("Once reached here: Did is not in whitelist")
	return false, errors.New("Is not in Whitelist")

}

func getAllowedDids(orgaID string) (AgentDidsResponse, error) {

	baseUrl := os.Getenv("BASEURL")
	pathUrl := os.Getenv("PATHURL")

	if baseUrl == "" {
		fmt.Println("Baseurl  is not set")
	} else {
		fmt.Println("URL and Path:", baseUrl, pathUrl)
	}

	fmt.Println("Orga ID should be did:web and is:", orgaID)

	//config abrufen
	//konfigurierbar machen
	//mock := "did:web:marketplace.dev.merlot-education.eu:participant:14e2471b-a276-3349-8a6e-caa941f9369b"
	url := fmt.Sprintf("%s/%s/%s", baseUrl, pathUrl, orgaID)
	fmt.Println("URL:", url)

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to make the request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed to get a valid response: status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read the response body: %v", err)
	}

	var allowedDidResponse AgentDidsResponse
	if err := json.Unmarshal(body, &allowedDidResponse); err != nil {
		log.Fatalf("Failed to unmarshal response: %v", err)
	}

	fmt.Println("Live: Agent DIDs that are retrieved from Merlot:", allowedDidResponse.AgentDids)

	return allowedDidResponse, nil
}
