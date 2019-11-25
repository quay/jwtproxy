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

package static

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/coreos/go-oidc/jose"
	log "github.com/sirupsen/logrus"

	"github.com/quay/jwtproxy/config"
	"github.com/quay/jwtproxy/jwt/claims"
	"github.com/quay/jwtproxy/stop"
)

func init() {
	claims.Register("static", constructor)
}

type Static struct {
	requiredClaims map[string]interface{}
}

func (scv *Static) Handle(req *http.Request, claims jose.Claims) error {
	log.Debugf("Verifying %d claims", len(scv.requiredClaims))
	for name, requiredValue := range scv.requiredClaims {
		log.Debugf("Verifying claim named: %s", name)
		// Look for the claim in the JWT claims.
		if found, ok := claims[name]; ok {
			if !reflect.DeepEqual(found, requiredValue) {
				return fmt.Errorf("Claim did not have the required value: %s", name)
			}
		} else {
			return fmt.Errorf("Required claim not found: %s", name)
		}
	}

	return nil
}

func (scv *Static) Stop() <-chan struct{} {
	return stop.AlreadyDone
}

func constructor(registrableComponentConfig config.RegistrableComponentConfig) (claims.Verifier, error) {
	return &Static{
		requiredClaims: registrableComponentConfig.Options,
	}, nil
}
