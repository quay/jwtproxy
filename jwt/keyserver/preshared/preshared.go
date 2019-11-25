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

package preshared

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
	"gopkg.in/yaml.v2"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/jwt/keyserver"
	"github.com/quay/jwtproxy/stop"
)

func init() {
	keyserver.RegisterReader("preshared", constructor)
}

type Preshared struct {
	*key.PublicKey
	Issuer string
}

type Config struct {
	Issuer        string `yaml:"issuer"`
	KeyID         string `yaml:"key_id"`
	PublicKeyPath string `yaml:"public_key_path"`
}

func constructor(registrableComponentConfig config.RegistrableComponentConfig) (keyserver.Reader, error) {
	var cfg Config
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	publicKey, err := loadPublicKey(cfg.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	return &Preshared{
		Issuer: cfg.Issuer,
		PublicKey: key.NewPublicKey(jose.JWK{
			ID:       cfg.KeyID,
			Use:      "sig",
			Type:     "RSA",
			Alg:      "RS256",
			Modulus:  publicKey.N,
			Exponent: publicKey.E,
		}),
	}, nil
}

func (preshared *Preshared) GetPublicKey(issuer string, keyID string) (*key.PublicKey, error) {
	if !strings.EqualFold(issuer, preshared.Issuer) || !strings.EqualFold(keyID, preshared.ID()) {
		return nil, errors.New("unknown public key")
	}
	return preshared.PublicKey, nil
}

func (preshared *Preshared) Stop() <-chan struct{} {
	return stop.AlreadyDone
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	publicKeyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	publicKeyBlock, _ := pem.Decode(publicKeyData)
	if publicKeyBlock == nil {
		return nil, errors.New("bad public key data")
	}

	if publicKeyBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unknown key type : %s", publicKeyBlock.Type)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parsed public key doesn't appear to be an RSA public key")
	}

	return rsaPublicKey, nil
}
