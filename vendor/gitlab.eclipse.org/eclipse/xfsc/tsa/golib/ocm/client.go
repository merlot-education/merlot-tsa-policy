package ocm

import (
	"bytes"
	"context"
	"encoding/json"
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
	if len(creddef) < 6 {
		return false, nil
	}
	endOfDid := strings.Index(creddef, ":")
	//change for variablilty in did length
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
	allowed, err = getAllowedDids(issuer)

	if err != nil {
		log.Println("Error retrieving the Allowed Dids")
		return false, nil
	}

	//check whitelisting
	for _, v := range allowed.AgentDids {
		if v == did {
			log.Println("Is in whitelist. Value:", v)
			return true, nil
		}
	}

	return false, nil

}

func getAllowedDids(orgaID string) (AgentDidsResponse, error) {

	//rename
	baseUrl := os.Getenv("BASEURL_DID_AUTH")
	pathUrl := os.Getenv("PATHURL_DID_AUTH")

	if baseUrl == "" {
		fmt.Println("Baseurl  is not set")
	} else {
		fmt.Println("URL and Path:", baseUrl, pathUrl)
	}

	log.Println("Orga ID should be did:web and is:", orgaID)

	url := fmt.Sprintf("%s/%s/%s", baseUrl, pathUrl, orgaID)
	log.Println("URL:", url)

	resp, err := http.Get(url)
	if err != nil {
		//return error
		fmt.Println("Failed to make the request:", err)

	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Failed to get a valid response: status code ", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read the response body: ", err)
	}

	var allowedDidResponse AgentDidsResponse
	if err := json.Unmarshal(body, &allowedDidResponse); err != nil {
		log.Println("Failed to unmarshal response: ", err)
	}

	log.Println("Agent DIDs that are retrieved from Merlot:", allowedDidResponse.AgentDids)

	return allowedDidResponse, nil
}
