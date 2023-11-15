package policy

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type signAdapter struct {
	signer         Signer
	namespace, key string
	alg            jwa.SignatureAlgorithm
}

func (a *signAdapter) Sign(data []byte, _ interface{}) ([]byte, error) {
	return a.signer.Sign(context.Background(), a.namespace, a.key, data)
}

func (a *signAdapter) Algorithm() jwa.SignatureAlgorithm {
	return jwaSignatureAlgorithmVault(a.namespace, a.key)
}

// sign uses jws.RegisterSigner to enable an adapter interface implementation
// to call external signer service.
func (s *Service) sign(namespace, key string, data []byte) ([]byte, error) {
	sigalg := jwaSignatureAlgorithmVault(namespace, key)

	jws.RegisterSigner(jwaSignatureAlgorithmVault(namespace, key), func(alg jwa.SignatureAlgorithm) jws.SignerFactory {
		return jws.SignerFactoryFn(func() (jws.Signer, error) {
			return &signAdapter{
				signer:    s.signer,
				namespace: namespace,
				key:       key,
				alg:       sigalg,
			}, nil
		})
	}(sigalg))

	signature, err := jws.Sign(
		nil,
		jws.WithKey(sigalg, nil),
		jws.WithDetachedPayload(data),
	)

	return signature, err
}

func jwaSignatureAlgorithmVault(namespace string, key string) jwa.SignatureAlgorithm {
	return jwa.SignatureAlgorithm(fmt.Sprintf("vault_%s_%s", namespace, key))
}
