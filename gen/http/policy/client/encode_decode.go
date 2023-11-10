// Code generated by goa v3.14.0, DO NOT EDIT.
//
// policy HTTP client encoders and decoders
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	policy "gitlab.eclipse.org/eclipse/xfsc/tsa/policy/gen/policy"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// BuildEvaluateRequest instantiates a HTTP request object with method and path
// set to call the "policy" service "Evaluate" endpoint
func (c *Client) BuildEvaluateRequest(ctx context.Context, v any) (*http.Request, error) {
	var (
		repository string
		group      string
		policyName string
		version    string
	)
	{
		p, ok := v.(*policy.EvaluateRequest)
		if !ok {
			return nil, goahttp.ErrInvalidType("policy", "Evaluate", "*policy.EvaluateRequest", v)
		}
		repository = p.Repository
		group = p.Group
		policyName = p.PolicyName
		version = p.Version
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: EvaluatePolicyPath(repository, group, policyName, version)}
	req, err := http.NewRequest("GET", u.String(), nil)
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
func EncodeEvaluateRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, any) error {
	return func(req *http.Request, v any) error {
		p, ok := v.(*policy.EvaluateRequest)
		if !ok {
			return goahttp.ErrInvalidType("policy", "Evaluate", "*policy.EvaluateRequest", v)
		}
		if p.EvaluationID != nil {
			head := *p.EvaluationID
			req.Header.Set("x-evaluation-id", head)
		}
		if p.TTL != nil {
			head := *p.TTL
			headStr := strconv.Itoa(head)
			req.Header.Set("x-cache-ttl", headStr)
		}
		body := p.Input
		if err := encoder(req).Encode(&body); err != nil {
			return goahttp.ErrEncodingError("policy", "Evaluate", err)
		}
		return nil
	}
}

// DecodeEvaluateResponse returns a decoder for responses returned by the
// policy Evaluate endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeEvaluateResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (any, error) {
	return func(resp *http.Response) (any, error) {
		if restoreBody {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = io.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var (
				body any
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("policy", "Evaluate", err)
			}
			var (
				eTag string
			)
			eTagRaw := resp.Header.Get("Etag")
			if eTagRaw == "" {
				err = goa.MergeErrors(err, goa.MissingFieldError("ETag", "header"))
			}
			eTag = eTagRaw
			if err != nil {
				return nil, goahttp.ErrValidationError("policy", "Evaluate", err)
			}
			res := NewEvaluateResultOK(body, eTag)
			return res, nil
		default:
			body, _ := io.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "Evaluate", resp.StatusCode, string(body))
		}
	}
}

// BuildLockRequest instantiates a HTTP request object with method and path set
// to call the "policy" service "Lock" endpoint
func (c *Client) BuildLockRequest(ctx context.Context, v any) (*http.Request, error) {
	var (
		repository string
		group      string
		policyName string
		version    string
	)
	{
		p, ok := v.(*policy.LockRequest)
		if !ok {
			return nil, goahttp.ErrInvalidType("policy", "Lock", "*policy.LockRequest", v)
		}
		repository = p.Repository
		group = p.Group
		policyName = p.PolicyName
		version = p.Version
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: LockPolicyPath(repository, group, policyName, version)}
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
func DecodeLockResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (any, error) {
	return func(resp *http.Response) (any, error) {
		if restoreBody {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = io.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := io.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "Lock", resp.StatusCode, string(body))
		}
	}
}

// BuildUnlockRequest instantiates a HTTP request object with method and path
// set to call the "policy" service "Unlock" endpoint
func (c *Client) BuildUnlockRequest(ctx context.Context, v any) (*http.Request, error) {
	var (
		repository string
		group      string
		policyName string
		version    string
	)
	{
		p, ok := v.(*policy.UnlockRequest)
		if !ok {
			return nil, goahttp.ErrInvalidType("policy", "Unlock", "*policy.UnlockRequest", v)
		}
		repository = p.Repository
		group = p.Group
		policyName = p.PolicyName
		version = p.Version
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: UnlockPolicyPath(repository, group, policyName, version)}
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
func DecodeUnlockResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (any, error) {
	return func(resp *http.Response) (any, error) {
		if restoreBody {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = io.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return nil, nil
		default:
			body, _ := io.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "Unlock", resp.StatusCode, string(body))
		}
	}
}

// BuildExportBundleRequest instantiates a HTTP request object with method and
// path set to call the "policy" service "ExportBundle" endpoint
func (c *Client) BuildExportBundleRequest(ctx context.Context, v any) (*http.Request, error) {
	var (
		repository string
		group      string
		policyName string
		version    string
	)
	{
		p, ok := v.(*policy.ExportBundleRequest)
		if !ok {
			return nil, goahttp.ErrInvalidType("policy", "ExportBundle", "*policy.ExportBundleRequest", v)
		}
		repository = p.Repository
		group = p.Group
		policyName = p.PolicyName
		version = p.Version
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: ExportBundlePolicyPath(repository, group, policyName, version)}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("policy", "ExportBundle", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// DecodeExportBundleResponse returns a decoder for responses returned by the
// policy ExportBundle endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeExportBundleResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (any, error) {
	return func(resp *http.Response) (any, error) {
		if restoreBody {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = io.NopCloser(bytes.NewBuffer(b))
			}()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var (
				contentType        string
				contentLength      int
				contentDisposition string
				err                error
			)
			contentTypeRaw := resp.Header.Get("Content-Type")
			if contentTypeRaw == "" {
				err = goa.MergeErrors(err, goa.MissingFieldError("content-type", "header"))
			}
			contentType = contentTypeRaw
			{
				contentLengthRaw := resp.Header.Get("Content-Length")
				if contentLengthRaw == "" {
					return nil, goahttp.ErrValidationError("policy", "ExportBundle", goa.MissingFieldError("content-length", "header"))
				}
				v, err2 := strconv.ParseInt(contentLengthRaw, 10, strconv.IntSize)
				if err2 != nil {
					err = goa.MergeErrors(err, goa.InvalidFieldTypeError("content-length", contentLengthRaw, "integer"))
				}
				contentLength = int(v)
			}
			contentDispositionRaw := resp.Header.Get("Content-Disposition")
			if contentDispositionRaw == "" {
				err = goa.MergeErrors(err, goa.MissingFieldError("content-disposition", "header"))
			}
			contentDisposition = contentDispositionRaw
			if err != nil {
				return nil, goahttp.ErrValidationError("policy", "ExportBundle", err)
			}
			res := NewExportBundleResultOK(contentType, contentLength, contentDisposition)
			return res, nil
		default:
			body, _ := io.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "ExportBundle", resp.StatusCode, string(body))
		}
	}
}

// BuildListPoliciesRequest instantiates a HTTP request object with method and
// path set to call the "policy" service "ListPolicies" endpoint
func (c *Client) BuildListPoliciesRequest(ctx context.Context, v any) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: ListPoliciesPolicyPath()}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("policy", "ListPolicies", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeListPoliciesRequest returns an encoder for requests sent to the policy
// ListPolicies server.
func EncodeListPoliciesRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, any) error {
	return func(req *http.Request, v any) error {
		p, ok := v.(*policy.PoliciesRequest)
		if !ok {
			return goahttp.ErrInvalidType("policy", "ListPolicies", "*policy.PoliciesRequest", v)
		}
		values := req.URL.Query()
		if p.Locked != nil {
			values.Add("locked", fmt.Sprintf("%v", *p.Locked))
		}
		if p.Rego != nil {
			values.Add("rego", fmt.Sprintf("%v", *p.Rego))
		}
		if p.Data != nil {
			values.Add("data", fmt.Sprintf("%v", *p.Data))
		}
		if p.DataConfig != nil {
			values.Add("dataConfig", fmt.Sprintf("%v", *p.DataConfig))
		}
		req.URL.RawQuery = values.Encode()
		return nil
	}
}

// DecodeListPoliciesResponse returns a decoder for responses returned by the
// policy ListPolicies endpoint. restoreBody controls whether the response body
// should be restored after having been read.
func DecodeListPoliciesResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (any, error) {
	return func(resp *http.Response) (any, error) {
		if restoreBody {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = io.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var (
				body ListPoliciesResponseBody
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("policy", "ListPolicies", err)
			}
			err = ValidateListPoliciesResponseBody(&body)
			if err != nil {
				return nil, goahttp.ErrValidationError("policy", "ListPolicies", err)
			}
			res := NewListPoliciesPoliciesResultOK(&body)
			return res, nil
		default:
			body, _ := io.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "ListPolicies", resp.StatusCode, string(body))
		}
	}
}

// BuildSubscribeForPolicyChangeRequest instantiates a HTTP request object with
// method and path set to call the "policy" service "SubscribeForPolicyChange"
// endpoint
func (c *Client) BuildSubscribeForPolicyChangeRequest(ctx context.Context, v any) (*http.Request, error) {
	var (
		repository string
		group      string
		policyName string
		version    string
	)
	{
		p, ok := v.(*policy.SubscribeRequest)
		if !ok {
			return nil, goahttp.ErrInvalidType("policy", "SubscribeForPolicyChange", "*policy.SubscribeRequest", v)
		}
		repository = p.Repository
		group = p.Group
		policyName = p.PolicyName
		version = p.Version
	}
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: SubscribeForPolicyChangePolicyPath(repository, group, policyName, version)}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, goahttp.ErrInvalidURL("policy", "SubscribeForPolicyChange", u.String(), err)
	}
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	return req, nil
}

// EncodeSubscribeForPolicyChangeRequest returns an encoder for requests sent
// to the policy SubscribeForPolicyChange server.
func EncodeSubscribeForPolicyChangeRequest(encoder func(*http.Request) goahttp.Encoder) func(*http.Request, any) error {
	return func(req *http.Request, v any) error {
		p, ok := v.(*policy.SubscribeRequest)
		if !ok {
			return goahttp.ErrInvalidType("policy", "SubscribeForPolicyChange", "*policy.SubscribeRequest", v)
		}
		body := NewSubscribeForPolicyChangeRequestBody(p)
		if err := encoder(req).Encode(&body); err != nil {
			return goahttp.ErrEncodingError("policy", "SubscribeForPolicyChange", err)
		}
		return nil
	}
}

// DecodeSubscribeForPolicyChangeResponse returns a decoder for responses
// returned by the policy SubscribeForPolicyChange endpoint. restoreBody
// controls whether the response body should be restored after having been read.
func DecodeSubscribeForPolicyChangeResponse(decoder func(*http.Response) goahttp.Decoder, restoreBody bool) func(*http.Response) (any, error) {
	return func(resp *http.Response) (any, error) {
		if restoreBody {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(b))
			defer func() {
				resp.Body = io.NopCloser(bytes.NewBuffer(b))
			}()
		} else {
			defer resp.Body.Close()
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var (
				body any
				err  error
			)
			err = decoder(resp).Decode(&body)
			if err != nil {
				return nil, goahttp.ErrDecodingError("policy", "SubscribeForPolicyChange", err)
			}
			return body, nil
		default:
			body, _ := io.ReadAll(resp.Body)
			return nil, goahttp.ErrInvalidResponse("policy", "SubscribeForPolicyChange", resp.StatusCode, string(body))
		}
	}
}

// unmarshalPolicyResponseBodyToPolicyPolicy builds a value of type
// *policy.Policy from a value of type *PolicyResponseBody.
func unmarshalPolicyResponseBodyToPolicyPolicy(v *PolicyResponseBody) *policy.Policy {
	res := &policy.Policy{
		Repository: *v.Repository,
		PolicyName: *v.PolicyName,
		Group:      *v.Group,
		Version:    *v.Version,
		Rego:       v.Rego,
		Data:       v.Data,
		DataConfig: v.DataConfig,
		Locked:     *v.Locked,
		LastUpdate: *v.LastUpdate,
	}

	return res
}
