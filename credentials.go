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

package hmacproxy

import (
	"fmt"
)

type Credential interface {
	KeyID() string
	KeySecret() string
}

type CredentialStore interface {
	LoadCredential(keyID, serviceName, regionName string) (Credential, error)
}

type SingleAccessKey struct {
	ID     string
	Secret string
}

func (s SingleAccessKey) KeyID() string {
	return s.ID
}

func (s SingleAccessKey) KeySecret() string {
	return s.Secret
}

func (s SingleAccessKey) LoadCredential(keyID, _, _ string) (Credential, error) {
	if keyID != s.ID {
		return nil, fmt.Errorf("Unknown key with key id: %s", keyID)
	}
	return s, nil
}
