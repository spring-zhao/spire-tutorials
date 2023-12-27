package helper

import (
	"code.byted.org/security/volczti-helper/log"

	"github.com/pkg/errors"
)

// // SVID represents a JWT-SVID.
// type JWTToken struct {

// 	// ID is the VOLC ID of the JWT-SVID as present in the 'sub' claim
// 	ID VID
// 	// Audience is the intended recipients of JWT-SVID as present in the 'aud' claim
// 	Audience []string
// 	// Expiry is the expiration time of JWT-SVID as present in 'exp' claim
// 	Expiry time.Time
// 	// Claims is the parsed claims from token
// 	Claims map[string]interface{}

// 	// token is the serialized JWT token
// 	token string
// }

// type JWTBundle struct {
// 	trustDomain    string
// 	jwtAuthorities map[string]crypto.PublicKey
// }

func (h *Helper) FetchJwtToken() (tok string, err error) {

	if h == nil || h.cache == nil {
		err = errors.Errorf("helper or helper.cache invalid")
		log.Error(err.Error())
		return
	}

	return h.cache.FetchJwtToken()
}

func (h *Helper) FetchJwtTokenBundle() (string, error) {

	if h == nil || h.cache == nil {
		err := errors.Errorf("helper or helper.cache invalid")
		log.Error(err.Error())
		return "", err
	}

	return h.cache.FetchJwtToken()
}

// // VerifyToken TODO:
// // 1. cache the valid token, can greatly low the latency of verification
// func (t *Helper) VerifyToken(token string) (*JWTToken, error) {

// 	var err error

// 	// Parse and validate token against fetched bundle from jwtSource,
// 	// an alternative is using `workloadapi.ValidateJWTSVID` that will
// 	// attest against SPIRE on each call and validate token
// 	svid, err := jwtsvid.ParseAndValidate(token, t.jwtSource, []string{VOLC_ZTI_AUDIENCE})
// 	if err != nil {
// 		log.Error("Invalid token", "err", err)
// 		err := errors.Errorf("Invalid token, err:%v", err)
// 		return nil, err
// 	}

// 	vid, err := FromSpiffeID(&svid.ID)
// 	if err != nil {
// 		log.Error("FromSpiffeID, SPIFFE ID to VOLC ID failed", "err", err)
// 		err := errors.Errorf("FromSpiffeID, SPIFFE ID to VOLC ID failed, err:%v", err)
// 		return nil, err
// 	}

// 	jwtid := &JWTToken{
// 		ID:       *vid,
// 		Audience: svid.Audience,
// 		Expiry:   svid.Expiry,
// 		Claims:   svid.Claims,
// 		token:    svid.Marshal(),
// 	}

// 	return jwtid, nil
// }

// // ParseAndValidate parses and validates a JWT-SVID token and returns the
// // JWT-SVID. The JWT-SVID signature is verified using the JWT bundle source.
// func ParseAndValidate(token string, bundles jwtbundle.Source, audience []string) (*SVID, error) {
// 	return parse(token, audience, func(tok *jwt.JSONWebToken, trustDomain spiffeid.TrustDomain) (map[string]interface{}, error) {
// 		// Obtain the key ID from the header
// 		keyID := tok.Headers[0].KeyID
// 		if keyID == "" {
// 			return nil, errors.New("token header missing key id")
// 		}

// 		// Get JWT Bundle
// 		bundle, err := bundles.GetJWTBundleForTrustDomain(trustDomain)
// 		if err != nil {
// 			return nil, errors.New("no bundle found for trust domain %q", trustDomain)
// 		}

// 		// Find JWT authority using the key ID from the token header
// 		authority, ok := bundle.FindJWTAuthority(keyID)
// 		if !ok {
// 			return nil, errors.New("no JWT authority %q found for trust domain %q", keyID, trustDomain)
// 		}

// 		// Obtain and verify the token claims using the obtained JWT authority
// 		claimsMap := make(map[string]interface{})
// 		if err := tok.Claims(authority, &claimsMap); err != nil {
// 			return nil, errors.New("unable to get claims from token: %v", err)
// 		}

// 		return claimsMap, nil
// 	})
// }

// func parse(token string, audience []string, getClaims tokenValidator) (*SVID, error) {
// 	// Parse serialized token
// 	tok, err := jwt.ParseSigned(token)
// 	if err != nil {
// 		return nil, errors.New("unable to parse JWT token")
// 	}

// 	// Validates supported token signed algorithm
// 	if err := validateTokenAlgorithm(tok); err != nil {
// 		return nil, err
// 	}

// 	// Parse out the unverified claims. We need to look up the key by the trust
// 	// domain of the SPIFFE ID.
// 	var claims jwt.Claims
// 	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
// 		return nil, errors.Errorf("unable to get claims from token: %v", err)
// 	}

// 	switch {
// 	case claims.Subject == "":
// 		return nil, errors.New("token missing subject claim")
// 	case claims.Expiry == nil:
// 		return nil, errors.New("token missing exp claim")
// 	}

// 	spiffeID, err := spiffeid.FromString(claims.Subject)
// 	if err != nil {
// 		return nil, errors.Errorf("token has an invalid subject claim: %v", err)
// 	}

// 	// Create generic map of claims
// 	claimsMap, err := getClaims(tok, spiffeID.TrustDomain())
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Validate the standard claims.
// 	if err := claims.Validate(jwt.Expected{
// 		Audience: audience,
// 		Time:     time.Now(),
// 	}); err != nil {
// 		// Convert expected validation errors for pretty errors
// 		switch err {
// 		case jwt.ErrExpired:
// 			err = errors.New("token has expired")
// 		case jwt.ErrInvalidAudience:
// 			err = errors.New("expected audience in %q (audience=%q)", audience, claims.Audience)
// 		}
// 		return nil, err
// 	}

// 	return &SVID{
// 		ID:       spiffeID,
// 		Audience: claims.Audience,
// 		Expiry:   claims.Expiry.Time().UTC(),
// 		Claims:   claimsMap,
// 		token:    token,
// 	}, nil
// }

// // validateTokenAlgorithm json web token have only one header, and it is signed for a supported algorithm
// func validateTokenAlgorithm(tok *jwt.JSONWebToken) error {
// 	// Only one header is expected
// 	if len(tok.Headers) != 1 {
// 		return fmt.Errorf("expected a single token header; got %d", len(tok.Headers))
// 	}

// 	// Make sure it has an algorithm supported by JWT-SVID
// 	alg := tok.Headers[0].Algorithm
// 	switch jose.SignatureAlgorithm(alg) {
// 	case jose.RS256, jose.RS384, jose.RS512,
// 		jose.ES256, jose.ES384, jose.ES512,
// 		jose.PS256, jose.PS384, jose.PS512:
// 	default:
// 		return errors.Errorf("unsupported token signature algorithm %q", alg)
// 	}

// 	return nil
// }

// func ParseJwtTokenInsecure(token string) (*JWTToken, error) {
// 	svid, err := jwtsvid.ParseInsecure(token, []string{VOLC_ZTI_AUDIENCE})
// 	if err != nil {
// 		log.Error("Invalid token", "err", err)
// 		err := errors.Errorf("Invalid token, err:%v", err)
// 		return nil, err
// 	}

// 	vid, err := FromSpiffeID(&svid.ID)
// 	if err != nil {
// 		log.Error("FromSpiffeID, SPIFFE ID to VOLC ID failed", "err", err)
// 		err := errors.Errorf("FromSpiffeID, SPIFFE ID to VOLC ID failed, err:%v", err)
// 		return nil, err
// 	}

// 	jwtid := &JWTToken{
// 		ID:       *vid,
// 		Audience: svid.Audience,
// 		Expiry:   svid.Expiry,
// 		Claims:   svid.Claims,
// 		token:    svid.Marshal(),
// 	}

// 	return jwtid, nil
// }
