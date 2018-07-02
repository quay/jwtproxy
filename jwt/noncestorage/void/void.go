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

package void

import (
	"time"

	"github.com/eclipse-che-staging/jwtproxy/config"
	"github.com/eclipse-che-staging/jwtproxy/jwt/noncestorage"
	"github.com/eclipse-che-staging/jwtproxy/stop"
)

func init() {
	noncestorage.Register("void", constructor)
}

type Void struct {}

func constructor(registrableComponentConfig config.RegistrableComponentConfig) (noncestorage.NonceStorage, error) {
	return &Void{}, nil
}
func (ln *Void) Verify(nonce string, expiration time.Time) bool {
	return true
}

func (ln *Void) Stop() <-chan struct{} {
	return stop.AlreadyDone
}
