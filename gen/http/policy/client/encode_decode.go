// Code generated by goa v3.7.0, DO NOT EDIT.
//
// policy HTTP client encoders and decoders
//
// Command:
// $ goa gen code.vereign.com/gaiax/tsa/policy/design

package client

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"

	policy "code.vereign.com/gaiax/tsa/policy/gen/policy"
	goahttp "goa.design/goa/v3/http"
)

// BuildEvaluateRequest instantiates a HTTP request object with method and path
// set to call the "policy" service "Evaluate" endpoint
func (c *Client) BuildEvaluateRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	var (
		group      string
		policyName string
		version    string
	)
	{
		p, ok := v.(*policy.EvaluateRequest)
		if !ok {
			return nil, goahttp.ErrInvalidType("policy", "Evaluate", "*policy.EvaluateRequest", v)
		}
		group = p.Group
		policyName = p.PolicyName
		version = p.Version
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: EvaluatePolicyPath(group, policyName, version)}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("policy", "Evaluate", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeEvaluateRequest returns an encoder for requests sent to the policy
// Evaluate server.
func EncodeEvaluateRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, interface{}) error {
	return func(req *http.Request, v interface{}) error {
		p, ok := v.(*policy.EvaluateRequest)
		if !ok {
			return goahttp.ErrInvalidType("policy", "Evaluate", "*policy.EvaluateRequest", v)
		}
		body := NewEvaluateRequestBody(p)
		if err := encoder(req).Encode(&body); err != nil {
			return goahttp.ErrEncodingError("policy", "Evaluate", err)
		}
		return nil
	}
}

// DecodeEvaluateResponse returns a decoder for responses returned by the
// policy Evaluate endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeEvaluateResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var (
				body EvaluateResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("policy", "Evaluate", err)
			}
			err = ValidateEvaluateResponseBody(&body)
			if err != nil {
				return nil, goahttp.ErrValidationError("policy", "Evaluate", err)
			}
			res := NewEvaluateResultOK(&body)
			return res, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "Evaluate", resp.StatusCode, string(body))
		}
	}
}

// BuildLockRequest instantiates a HTTP request object with method and path set
// to call the "policy" service "Lock" endpoint
func (c *Client) BuildLockRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	var (
		group      string
		policyName string
		version    string
	)
	{
		p, ok := v.(*policy.LockRequest)
		if !ok {
			return nil, goahttp.ErrInvalidType("policy", "Lock", "*policy.LockRequest", v)
		}
		group = p.Group
		policyName = p.PolicyName
		version = p.Version
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: LockPolicyPath(group, policyName, version)}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("policy", "Lock", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// DecodeLockResponse returns a decoder for responses returned by the policy
// Lock endpoint. restoreBody controls whether the response body should be
// restored after having been read.
func DecodeLockResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "Lock", resp.StatusCode, string(body))
		}
	}
}

// BuildUnlockRequest instantiates a HTTP request object with method and path
// set to call the "policy" service "Unlock" endpoint
func (c *Client) BuildUnlockRequest(ctx context.Context, v interface{}) (*http.Request, error) {
	var (
		group      string
		policyName string
		version    string
	)
	{
		p, ok := v.(*policy.UnlockRequest)
		if !ok {
			return nil, goahttp.ErrInvalidType("policy", "Unlock", "*policy.UnlockRequest", v)
		}
		group = p.Group
		policyName = p.PolicyName
		version = p.Version
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: UnlockPolicyPath(group, policyName, version)}
	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("policy", "Unlock", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// DecodeUnlockResponse returns a decoder for responses returned by the policy
// Unlock endpoint. restoreBody controls whether the response body should be
// restored after having been read.
func DecodeUnlockResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (interface{}, error) {
	return func(resp *http.Response) (interface{}, error) {
		if restoreBody {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "Unlock", resp.StatusCode, string(body))
		}
	}
}
