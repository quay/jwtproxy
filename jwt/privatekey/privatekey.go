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

package privatekey

import (
	"fmt"

	"github.com/coreos/go-oidc/key"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/stop"
)

type PrivateKey interface {
	stop.Stoppable
	GetPrivateKey() (*key.PrivateKey, error)
}

type Constructor func(config.RegistrableComponentConfig, config.SignerParams) (PrivateKey, error)

var privatekeys = make(map[string]Constructor)

func Register(name string, pkc Constructor) {
	if pkc == nil {
		panic("server: could not register nil Constructor")
	}
	if _, dup := privatekeys[name]; dup {
		panic("server: could not register duplicate Constructor: " + name)
	}
	privatekeys[name] = pkc
}

func New(cfg config.RegistrableComponentConfig, params config.SignerParams) (PrivateKey, error) {
	pkc, ok := privatekeys[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("server: unknown Constructor %q (forgotten import?)", cfg.Type)
	}
	return pkc(cfg, params)
}
