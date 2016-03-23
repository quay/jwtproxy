// Copyright 2015 CoreOS, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwt

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos-inc/jwtproxy/jwt/keyserver"
	"github.com/coreos-inc/jwtproxy/jwt/noncestorage"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"
)

func Sign(req *http.Request, issuer string, key *key.PrivateKey, nonceGenerator noncestorage.NonceStorage, maxSkew time.Duration) error {
	// Create Claims.
	nonce, err := nonceGenerator.Generate()
	if err != nil {
		return err
	}

	claims := jose.Claims{
		"kid": key.ID(),
		"iss": issuer,
		"aud": req.URL.Host,
		"iat": time.Now().Unix(),
		"nbf": time.Now().Add(-maxSkew).Unix(),
		"exp": time.Now().Add(maxSkew).Unix(),
		"jti": nonce,
	}

	// Create JWT.
	jwt, err := jose.NewSignedJWT(claims, key.Signer())

	// Add it as a header in the request.
	req.Header.Add("Authorization", "Bearer "+jwt.Encode())

	return nil
}

func Verify(req *http.Request, keyServer keyserver.Reader, nonceVerifier noncestorage.NonceStorage, audience *url.URL, maxSkew time.Duration) error {
	// Extract token from request.
	token, err := oidc.ExtractBearerToken(req)
	if err != nil {
		return errors.New("no JWT found")
	}

	// Parse token.
	jwt, err := jose.ParseJWT(token)
	if err != nil {
		return errors.New("could not parse JWT")
	}

	claims, err := jwt.Claims()
	if err != nil {
		return errors.New("could not parse JWT claims")
	}

	// Verify claims.
	now := time.Now().UTC()

	kid, exists, err := claims.StringClaim("kid")
	if !exists || err != nil {
		return errors.New("missing or invalid 'kid' claim")
	}
	iss, exists, err := claims.StringClaim("iss")
	if !exists || err != nil {
		return errors.New("missing or invalid 'iss' claim")
	}
	aud, exists, err := claims.StringClaim("aud")
	if !exists || err != nil || !verifyAudience(aud, audience) {
		return errors.New("missing or invalid 'aud' claim")
	}
	exp, exists, err := claims.TimeClaim("exp")
	if !exists || err != nil || exp.Before(now) {
		return errors.New("missing or invalid 'exp' claim")
	}
	nbf, exists, err := claims.TimeClaim("nbf")
	if !exists || err != nil || nbf.After(now) {
		return errors.New("missing or invalid 'nbf' claim")
	}
	_, exists, err = claims.TimeClaim("iat")
	if !exists || err != nil {
		return errors.New("missing or invalid 'iat' claim")
	}
	jti, exists, err := claims.StringClaim("jti")
	if !exists || err != nil || !nonceVerifier.Verify(jti, exp) {
		return errors.New("missing or invalid 'jti' claim")
	}

	// Verify signature.
	publicKey, err := keyServer.GetPublicKey(iss, kid)
	if err != nil {
		return err
	}
	verifier, err := publicKey.Verifier()
	if err != nil {
		return err
	}
	if verifier.Verify(jwt.Signature, []byte(jwt.Data())) != nil {
		return errors.New("invalid JWT signature")
	}

	return nil
}

func verifyAudience(aud string, audience *url.URL) bool {
	audURL, err := url.Parse(aud)
	if err != nil {
		return false
	}
	return strings.ToLower(audURL.Host+audURL.Path) == strings.ToLower(audience.Host+audience.Path)
}
