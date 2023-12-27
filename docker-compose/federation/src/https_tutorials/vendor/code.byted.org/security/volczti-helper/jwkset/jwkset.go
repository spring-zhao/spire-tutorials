package jwkset

import (
	"encoding/json"

	"code.byted.org/security/go-spiffe-v2/bundle/jwtbundle"
	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
)

type JWKBundle struct {
	TrustDomain string            `json:"TrustDomain"`
	Keys        []jose.JSONWebKey `json:"keys"`
}

type JWKSet struct {
	Bundles []JWKBundle `json:"Bundles"`
}

func (set *JWKSet) Marshal() ([]byte, error) {
	if set == nil {

		return nil, errors.Errorf("input invalid")
	}

	out, err := json.Marshal(set)

	return out, err
}

func UnMarshal(in []byte) (*JWKSet, error) {
	if in == nil {
		return nil, errors.Errorf("input invalid")
	}

	set := JWKSet{}

	err := json.Unmarshal(in, &set)

	return &set, err
}

func SpireJWTBundleSet2JWKSet(spireJWTBundleSet *jwtbundle.Set) (*JWKSet, error) {
	if spireJWTBundleSet == nil {
		return nil, errors.Errorf("input spireJWTBundleSet invalid")
	}

	bundles := spireJWTBundleSet.Bundles()

	jwkset := JWKSet{}

	for _, b := range bundles {

		jwkBundle := JWKBundle{
			TrustDomain: b.TrustDomain().String(),
		}

		for keyID, jwtAuthority := range b.JWTAuthorities() {
			jwkBundle.Keys = append(jwkBundle.Keys, jose.JSONWebKey{
				Key:   jwtAuthority,
				KeyID: keyID,
			})
		}

		jwkset.Bundles = append(jwkset.Bundles, jwkBundle)
	}

	return &jwkset, nil
}
