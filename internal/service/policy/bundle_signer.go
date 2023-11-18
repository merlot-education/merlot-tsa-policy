package policy

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const JwaVaultSignature jwa.SignatureAlgorithm = "VaultSignature"

// signAdapter implements the jws.Signer interface so that it
// can be used with the lestrrat-go library. Under the hood it
// does the signing by calling an external signer service.
type signAdapter struct {
	signer Signer
}

type signAdapterKey struct {
	Namespace string
	Key       string
}

func (a *signAdapter) Sign(data []byte, key interface{}) ([]byte, error) {
	signKey, ok := key.(*signAdapterKey)
	if !ok {
		return nil, fmt.Errorf("unexpected sign adapter key: %T", key)
	}

	return a.signer.Sign(context.Background(), signKey.Namespace, signKey.Key, data)
}

func (a *signAdapter) Algorithm() jwa.SignatureAlgorithm {
	return JwaVaultSignature
}

func (s *Service) sign(namespace, key string, data []byte) ([]byte, error) {
	signature, err := jws.Sign(
		nil,
		jws.WithKey(JwaVaultSignature, &signAdapterKey{
			Namespace: namespace,
			Key:       key,
		}),
		jws.WithDetachedPayload(data),
	)

	return signature, err
}
