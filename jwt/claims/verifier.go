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

package claims

import (
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/jose"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/stop"
)

type Constructor func(config.RegistrableComponentConfig) (Verifier, error)

type Verifier interface {
	stop.Stoppable
	Handle(*http.Request, jose.Claims) error
}

var verifierTypes = make(map[string]Constructor)

func Register(name string, vc Constructor) {
	if vc == nil {
		panic("server: could not register nil Verifier Constructor")
	}
	if _, dup := verifierTypes[name]; dup {
		panic("server: could not register duplicate Verifier Constructor type: " + name)
	}
	verifierTypes[name] = vc
}

func New(cfg config.RegistrableComponentConfig) (Verifier, error) {
	vc, ok := verifierTypes[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("server: unknown Verifier Constructor type %q (forgotten import?)", cfg.Type)
	}
	return vc(cfg)
}
