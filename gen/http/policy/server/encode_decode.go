// Code generated by goa v3.14.0, DO NOT EDIT.
//
// policy HTTP server encoders and decoders
//
// Command:
// $ goa gen gitlab.eclipse.org/eclipse/xfsc/tsa/policy/design

package server

import (
	"context"
	"io"
	"net/http"
	"strconv"

	policy "gitlab.eclipse.org/eclipse/xfsc/tsa/policy/gen/policy"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// EncodeEvaluateResponse returns an encoder for responses returned by the
// policy Evaluate endpoint.
func EncodeEvaluateResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(*policy.EvaluateResult)
		enc := encoder(ctx, w)
		body := res.Result
		w.Header().Set("Etag", res.ETag)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeEvaluateRequest returns a decoder for requests sent to the policy
// Evaluate endpoint.
func DecodeEvaluateRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			body any
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				err = nil
			} else {
				return nil, goa.DecodePayloadError(err.Error())
			}
		}

		var (
			repository   string
			group        string
			policyName   string
			version      string
			evaluationID *string
			ttl          *int

			params = mux.Vars(r)
		)
		repository = params["repository"]
		group = params["group"]
		policyName = params["policyName"]
		version = params["version"]
		evaluationIDRaw := r.Header.Get("x-evaluation-id")
		if evaluationIDRaw != "" {
			evaluationID = &evaluationIDRaw
		}
		{
			ttlRaw := r.Header.Get("x-cache-ttl")
			if ttlRaw != "" {
				v, err2 := strconv.ParseInt(ttlRaw, 10, strconv.IntSize)
				if err2 != nil {
					err = goa.MergeErrors(err, goa.InvalidFieldTypeError("ttl", ttlRaw, "integer"))
				}
				pv := int(v)
				ttl = &pv
			}
		}
		if err != nil {
			return nil, err
		}
		payload := NewEvaluateRequest(body, repository, group, policyName, version, evaluationID, ttl)

		return payload, nil
	}
}

// EncodeValidateResponse returns an encoder for responses returned by the
// policy Validate endpoint.
func EncodeValidateResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(*policy.EvaluateResult)
		enc := encoder(ctx, w)
		body := res.Result
		w.Header().Set("Etag", res.ETag)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeValidateRequest returns a decoder for requests sent to the policy
// Validate endpoint.
func DecodeValidateRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			body any
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				err = nil
			} else {
				return nil, goa.DecodePayloadError(err.Error())
			}
		}

		var (
			repository   string
			group        string
			policyName   string
			version      string
			evaluationID *string
			ttl          *int

			params = mux.Vars(r)
		)
		repository = params["repository"]
		group = params["group"]
		policyName = params["policyName"]
		version = params["version"]
		evaluationIDRaw := r.Header.Get("x-evaluation-id")
		if evaluationIDRaw != "" {
			evaluationID = &evaluationIDRaw
		}
		{
			ttlRaw := r.Header.Get("x-cache-ttl")
			if ttlRaw != "" {
				v, err2 := strconv.ParseInt(ttlRaw, 10, strconv.IntSize)
				if err2 != nil {
					err = goa.MergeErrors(err, goa.InvalidFieldTypeError("ttl", ttlRaw, "integer"))
				}
				pv := int(v)
				ttl = &pv
			}
		}
		if err != nil {
			return nil, err
		}
		payload := NewValidateEvaluateRequest(body, repository, group, policyName, version, evaluationID, ttl)

		return payload, nil
	}
}

// EncodeLockResponse returns an encoder for responses returned by the policy
// Lock endpoint.
func EncodeLockResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

// DecodeLockRequest returns a decoder for requests sent to the policy Lock
// endpoint.
func DecodeLockRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			repository string
			group      string
			policyName string
			version    string

			params = mux.Vars(r)
		)
		repository = params["repository"]
		group = params["group"]
		policyName = params["policyName"]
		version = params["version"]
		payload := NewLockRequest(repository, group, policyName, version)

		return payload, nil
	}
}

// EncodeUnlockResponse returns an encoder for responses returned by the policy
// Unlock endpoint.
func EncodeUnlockResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

// DecodeUnlockRequest returns a decoder for requests sent to the policy Unlock
// endpoint.
func DecodeUnlockRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			repository string
			group      string
			policyName string
			version    string

			params = mux.Vars(r)
		)
		repository = params["repository"]
		group = params["group"]
		policyName = params["policyName"]
		version = params["version"]
		payload := NewUnlockRequest(repository, group, policyName, version)

		return payload, nil
	}
}

// EncodeExportBundleResponse returns an encoder for responses returned by the
// policy ExportBundle endpoint.
func EncodeExportBundleResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(*policy.ExportBundleResult)
		w.Header().Set("Content-Type", res.ContentType)
		{
			val := res.ContentLength
			contentLengths := strconv.Itoa(val)
			w.Header().Set("Content-Length", contentLengths)
		}
		w.Header().Set("Content-Disposition", res.ContentDisposition)
		w.WriteHeader(http.StatusOK)
		return nil
	}
}

// DecodeExportBundleRequest returns a decoder for requests sent to the policy
// ExportBundle endpoint.
func DecodeExportBundleRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			repository string
			group      string
			policyName string
			version    string

			params = mux.Vars(r)
		)
		repository = params["repository"]
		group = params["group"]
		policyName = params["policyName"]
		version = params["version"]
		payload := NewExportBundleRequest(repository, group, policyName, version)

		return payload, nil
	}
}

// EncodePolicyPublicKeyResponse returns an encoder for responses returned by
// the policy PolicyPublicKey endpoint.
func EncodePolicyPublicKeyResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(any)
		enc := encoder(ctx, w)
		body := res
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodePolicyPublicKeyRequest returns a decoder for requests sent to the
// policy PolicyPublicKey endpoint.
func DecodePolicyPublicKeyRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			repository string
			group      string
			policyName string
			version    string

			params = mux.Vars(r)
		)
		repository = params["repository"]
		group = params["group"]
		policyName = params["policyName"]
		version = params["version"]
		payload := NewPolicyPublicKeyRequest(repository, group, policyName, version)

		return payload, nil
	}
}

// EncodeImportBundleResponse returns an encoder for responses returned by the
// policy ImportBundle endpoint.
func EncodeImportBundleResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(any)
		enc := encoder(ctx, w)
		body := res
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeImportBundleRequest returns a decoder for requests sent to the policy
// ImportBundle endpoint.
func DecodeImportBundleRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			length *int
			err    error
		)
		{
			lengthRaw := r.Header.Get("Content-Length")
			if lengthRaw != "" {
				v, err2 := strconv.ParseInt(lengthRaw, 10, strconv.IntSize)
				if err2 != nil {
					err = goa.MergeErrors(err, goa.InvalidFieldTypeError("length", lengthRaw, "integer"))
				}
				pv := int(v)
				length = &pv
			}
		}
		if err != nil {
			return nil, err
		}
		payload := NewImportBundlePayload(length)

		return payload, nil
	}
}

// EncodeListPoliciesResponse returns an encoder for responses returned by the
// policy ListPolicies endpoint.
func EncodeListPoliciesResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(*policy.PoliciesResult)
		enc := encoder(ctx, w)
		body := NewListPoliciesResponseBody(res)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeListPoliciesRequest returns a decoder for requests sent to the policy
// ListPolicies endpoint.
func DecodeListPoliciesRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			locked     *bool
			rego       *bool
			data       *bool
			dataConfig *bool
			err        error
		)
		{
			lockedRaw := r.URL.Query().Get("locked")
			if lockedRaw != "" {
				v, err2 := strconv.ParseBool(lockedRaw)
				if err2 != nil {
					err = goa.MergeErrors(err, goa.InvalidFieldTypeError("locked", lockedRaw, "boolean"))
				}
				locked = &v
			}
		}
		{
			regoRaw := r.URL.Query().Get("rego")
			if regoRaw != "" {
				v, err2 := strconv.ParseBool(regoRaw)
				if err2 != nil {
					err = goa.MergeErrors(err, goa.InvalidFieldTypeError("rego", regoRaw, "boolean"))
				}
				rego = &v
			}
		}
		{
			dataRaw := r.URL.Query().Get("data")
			if dataRaw != "" {
				v, err2 := strconv.ParseBool(dataRaw)
				if err2 != nil {
					err = goa.MergeErrors(err, goa.InvalidFieldTypeError("data", dataRaw, "boolean"))
				}
				data = &v
			}
		}
		{
			dataConfigRaw := r.URL.Query().Get("dataConfig")
			if dataConfigRaw != "" {
				v, err2 := strconv.ParseBool(dataConfigRaw)
				if err2 != nil {
					err = goa.MergeErrors(err, goa.InvalidFieldTypeError("dataConfig", dataConfigRaw, "boolean"))
				}
				dataConfig = &v
			}
		}
		if err != nil {
			return nil, err
		}
		payload := NewListPoliciesPoliciesRequest(locked, rego, data, dataConfig)

		return payload, nil
	}
}

// EncodeSetPolicyAutoImportResponse returns an encoder for responses returned
// by the policy SetPolicyAutoImport endpoint.
func EncodeSetPolicyAutoImportResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(any)
		enc := encoder(ctx, w)
		body := res
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeSetPolicyAutoImportRequest returns a decoder for requests sent to the
// policy SetPolicyAutoImport endpoint.
func DecodeSetPolicyAutoImportRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			body SetPolicyAutoImportRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateSetPolicyAutoImportRequestBody(&body)
		if err != nil {
			return nil, err
		}
		payload := NewSetPolicyAutoImportRequest(&body)

		return payload, nil
	}
}

// EncodePolicyAutoImportResponse returns an encoder for responses returned by
// the policy PolicyAutoImport endpoint.
func EncodePolicyAutoImportResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(any)
		enc := encoder(ctx, w)
		body := res
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// EncodeDeletePolicyAutoImportResponse returns an encoder for responses
// returned by the policy DeletePolicyAutoImport endpoint.
func EncodeDeletePolicyAutoImportResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(any)
		enc := encoder(ctx, w)
		body := res
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeDeletePolicyAutoImportRequest returns a decoder for requests sent to
// the policy DeletePolicyAutoImport endpoint.
func DecodeDeletePolicyAutoImportRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			body DeletePolicyAutoImportRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateDeletePolicyAutoImportRequestBody(&body)
		if err != nil {
			return nil, err
		}
		payload := NewDeletePolicyAutoImportRequest(&body)

		return payload, nil
	}
}

// EncodeSubscribeForPolicyChangeResponse returns an encoder for responses
// returned by the policy SubscribeForPolicyChange endpoint.
func EncodeSubscribeForPolicyChangeResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, any) error {
	return func(ctx context.Context, w http.ResponseWriter, v any) error {
		res, _ := v.(any)
		enc := encoder(ctx, w)
		body := res
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeSubscribeForPolicyChangeRequest returns a decoder for requests sent to
// the policy SubscribeForPolicyChange endpoint.
func DecodeSubscribeForPolicyChangeRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (any, error) {
	return func(r *http.Request) (any, error) {
		var (
			body SubscribeForPolicyChangeRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateSubscribeForPolicyChangeRequestBody(&body)
		if err != nil {
			return nil, err
		}

		var (
			repository string
			group      string
			policyName string
			version    string

			params = mux.Vars(r)
		)
		repository = params["repository"]
		group = params["group"]
		policyName = params["policyName"]
		version = params["version"]
		payload := NewSubscribeForPolicyChangeSubscribeRequest(&body, repository, group, policyName, version)

		return payload, nil
	}
}

// marshalPolicyPolicyToPolicyResponseBody builds a value of type
// *PolicyResponseBody from a value of type *policy.Policy.
func marshalPolicyPolicyToPolicyResponseBody(v *policy.Policy) *PolicyResponseBody {
	res := &PolicyResponseBody{
		Repository: v.Repository,
		PolicyName: v.PolicyName,
		Group:      v.Group,
		Version:    v.Version,
		Rego:       v.Rego,
		Data:       v.Data,
		DataConfig: v.DataConfig,
		Locked:     v.Locked,
		LastUpdate: v.LastUpdate,
	}

	return res
}
