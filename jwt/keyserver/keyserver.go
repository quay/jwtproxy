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

package keyserver

import (
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/key"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/stop"
)

var (
	ErrPublicKeyNotFound = errors.New("Could not find any matching public key")
	ErrPublicKeyExpired  = errors.New("Key has expired.")
)

type ReaderConstructor func(config.RegistrableComponentConfig) (Reader, error)
type ManagerConstructor func(config.RegistrableComponentConfig, config.SignerParams) (Manager, error)

type Reader interface {
	stop.Stoppable
	GetPublicKey(issuer string, keyID string) (*key.PublicKey, error)
}

type KeyPolicy struct {
	Expiration     *time.Time
	RotationPolicy *time.Duration
}

type Manager interface {
	stop.Stoppable
	VerifyPublicKey(keyID string) error
	PublishPublicKey(key *key.PublicKey, policy *KeyPolicy, signingKey *key.PrivateKey) *PublishResult
	DeletePublicKey(toRevoke *key.PrivateKey) error
}

var readers = make(map[string]ReaderConstructor)
var managers = make(map[string]ManagerConstructor)

func RegisterReader(name string, rc ReaderConstructor) {
	if rc == nil {
		panic("server: could not register nil ReaderConstructor")
	}
	if _, dup := readers[name]; dup {
		panic("server: could not register duplicate ReaderConstructor: " + name)
	}
	readers[name] = rc
}

func NewReader(cfg config.RegistrableComponentConfig) (Reader, error) {
	rc, ok := readers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("server: unknown ReaderConstructor %q (forgotten import?)", cfg.Type)
	}
	return rc(cfg)
}

func RegisterManager(name string, mc ManagerConstructor) {
	if mc == nil {
		panic("server: could not register nil ManagerConstructor")
	}
	if _, dup := managers[name]; dup {
		panic("server: could not register duplicate ManagerConstructor: " + name)
	}
	managers[name] = mc
}

func NewManager(cfg config.RegistrableComponentConfig, signerParams config.SignerParams) (Manager, error) {
	mc, ok := managers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("server: unknown ManagerConstructor %q (forgotten import?)", cfg.Type)
	}
	return mc(cfg, signerParams)
}
