// Copyright 2016 CoreOS, Inc
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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"
	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/stop"
	"github.com/stretchr/testify/assert"
)

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIBOAIBAAJAZ8S1IuX54K3bLtLuf47+etBSCcutD0GzUbog92BDmJwHlEiIPsdC
VEoHN0FnV3EXSuaBpoV2mQkwDcoyq9xWkwIDAQABAkBY47x25KIkwUlc1vvO8WM1
OXbNRVg+FX3SqKrMvf2poAfGIPM9tRwrvzs8vSTcXQus9EnUnem1LWIDUkFOSXKB
AiEAqLwPnbLlly8LP+vHt6FaYcAlEAHBAE7iT22qQAVjIHECIQCdb1H0IOt9y/HB
T+yXf/F/x37RfcVvujR8/ql+YqTpQwIgf+8m//CWN0zKAMsqgEZsmtTuxPYveaZV
3NdPUH9FK2ECID7TUqgSjwdHYLVdGLQoiY4NZW1iPGzmqNWMpsTZxqeTAiBjSNOD
im92fadzPg+oTXIQIjlHhGgf7CKb5VwFuH9+gA==
-----END RSA PRIVATE KEY-----
`

type testService struct {
	// privatekey
	privkey        *key.PrivateKey
	sendBadPrivKey bool

	// keyserver
	issuer        string
	sendBadPubKey bool

	// noncestorage
	refuseNonce bool
}

func (ts *testService) GetPrivateKey() (*key.PrivateKey, error) {
	p := *ts.privkey
	if ts.sendBadPrivKey {
		p.PrivateKey.D.Add(p.PrivateKey.D, big.NewInt(1))
	}

	return &p, nil
}

func (ts *testService) GetPublicKey(issuer string, keyID string) (*key.PublicKey, error) {
	if ts.issuer != issuer || ts.privkey.KeyID != keyID {
		return nil, errors.New("unknown public key")
	}

	jwk := ts.privkey.JWK()
	if ts.sendBadPubKey {
		jwk.Exponent = jwk.Exponent + 1
	}

	return key.NewPublicKey(jwk), nil
}

func (ts *testService) Verify(nonce string, expiration time.Time) bool {
	return !ts.refuseNonce
}

func (ts *testService) Stop() <-chan struct{} {
	return stop.AlreadyDone
}

func TestJWT(t *testing.T) {
	// Create a request to sign.
	req, _ := http.NewRequest("GET", "http://foo.bar:6666/ez", nil)

	// Create a public/private key pair used to sign/verify.
	pkb, _ := pem.Decode([]byte(privateKey))
	pkr, _ := x509.ParsePKCS1PrivateKey(pkb.Bytes)
	pk := &key.PrivateKey{
		KeyID:      "foo",
		PrivateKey: pkr,
	}

	// Create a test service to act as a keyserver and as a privatekey provider.
	services := &testService{
		privkey:        pk,
		sendBadPrivKey: false,
		issuer:         "issuer",
		sendBadPubKey:  false,
		refuseNonce:    false,
	}

	// Create a default (and valid) configuration to sign and verify requests.
	aud, _ := url.Parse("http://foo.bar:6666/ez")
	defaultConfig := &signAndVerifyParams{
		services: services,
		signerParams: config.SignerParams{
			Issuer:         services.issuer,
			ExpirationTime: 1 * time.Minute,
			MaxSkew:        1 * time.Minute,
			NonceLength:    8,
		},
		aud:     aud,
		maxSkew: time.Minute,
		maxTTL:  5 * time.Minute,
	}

	// Basic sign / verify.
	assert.Nil(t, signAndVerify(t, req, *defaultConfig, nil))

	// Alter a claim.
	claimModifier := func(req *http.Request) {
		token, err := oidc.ExtractBearerToken(req)
		assert.Nil(t, err)

		jwt, err := jose.ParseJWT(token)
		assert.Nil(t, err)

		claims, err := jwt.Claims()
		assert.Nil(t, err)

		// Alter the nonce.
		claims.Add("jti", "foo")

		// Create a new JWT having the same headers and signature but altered claims.
		// This is the only way to encode the claims with jose.
		modifiedJWT, err := jose.NewJWT(jwt.Header, claims)
		assert.Nil(t, err)
		modifiedJWT.Signature = jwt.Signature

		req.Header.Set("Authorization", "Bearer "+modifiedJWT.Encode())
	}
	assert.Error(t, signAndVerify(t, req, *defaultConfig, claimModifier))

	// Invalid nonce.
	cfg := *defaultConfig
	cfg.services.refuseNonce = true
	assert.Error(t, signAndVerify(t, req, cfg, nil))

	// Wrong audience.
	cfg = *defaultConfig
	cfg.aud, _ = url.Parse("http://dummy.silly/")
	assert.Error(t, signAndVerify(t, req, cfg, nil))

	req2, _ := http.NewRequest("GET", "http://silly.dummy/", nil)
	assert.Error(t, signAndVerify(t, req2, cfg, nil))

	// Signed for too long.
	cfg = *defaultConfig
	cfg.maxTTL = 30 * time.Second
	assert.Error(t, signAndVerify(t, req2, cfg, nil))

	// Expired.
	cfg = *defaultConfig
	cfg.signerParams.ExpirationTime = -time.Second
	assert.Error(t, signAndVerify(t, req, cfg, nil))

	// Used too early.
	// Abuse the signer's MaxSkew parameter to make the JWT valid only after a minute.
	cfg = *defaultConfig
	cfg.signerParams.MaxSkew = -time.Minute
	assert.Error(t, signAndVerify(t, req, cfg, nil))

	// Issued in the future.
	// Abuse the verifier's MaxSkew parameter to make the JWT looks like it has been signed in the
	// future.
	cfg = *defaultConfig
	cfg.maxSkew = -time.Minute
	assert.Error(t, signAndVerify(t, req, cfg, nil))

	// Mismatch public/private keys.
	cfg = *defaultConfig
	cfg.services.sendBadPubKey = true
	assert.Error(t, signAndVerify(t, req, cfg, nil))

	cfg = *defaultConfig
	cfg.services.sendBadPrivKey = true
	assert.Error(t, signAndVerify(t, req, cfg, nil))

	// Wrong issuer (leads to a bad/unknown private key).
	cfg = *defaultConfig
	cfg.signerParams.Issuer = "dummy"
	assert.Error(t, signAndVerify(t, req, cfg, nil))
}

type signAndVerifyParams struct {
	services *testService

	// Sign.
	signerParams config.SignerParams

	// Verify.
	aud     *url.URL
	maxSkew time.Duration
	maxTTL  time.Duration
}

type requestModifier func(req *http.Request)

func signAndVerify(t *testing.T, req *http.Request, p signAndVerifyParams, modify requestModifier) error {
	// Sign.
	pk, _ := p.services.GetPrivateKey()
	assert.Nil(t, Sign(req, pk, p.signerParams))

	// Modify signed request.
	if modify != nil {
		modify(req)
	}

	// Verify.
	_, err := Verify(req, p.services, p.services, p.aud, p.maxSkew, p.maxTTL)
	return err
}
