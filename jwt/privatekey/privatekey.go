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

package privatekey

import (
	"fmt"

	"github.com/coreos-inc/jwtproxy/config"
	"github.com/coreos/go-oidc/key"
)

type PrivateKey interface {
	GetPrivateKey() (*key.PrivateKey, error)
}

type PrivateKeyConstructor func(config.RegistrableComponentConfig, config.SignerParams) (PrivateKey, error)

var privatekeys = make(map[string]PrivateKeyConstructor)

func Register(name string, pkc PrivateKeyConstructor) {
	if pkc == nil {
		panic("server: could not register nil PrivateKeyConstructor")
	}
	if _, dup := privatekeys[name]; dup {
		panic("server: could not register duplicate PrivateKeyConstructor: " + name)
	}
	privatekeys[name] = pkc
}

func New(cfg config.RegistrableComponentConfig, params config.SignerParams) (PrivateKey, error) {
	pkc, ok := privatekeys[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("server: unknown PrivateKeyConstructor %q (forgotten import?)", cfg.Type)
	}
	return pkc(cfg, params)
}
