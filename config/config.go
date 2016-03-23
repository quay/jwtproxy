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

package config

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"

	"gopkg.in/yaml.v2"
)

// URL is a custom URL type that allows validation at configuration load time.
type URL struct {
	*url.URL
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for URLs.
func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	urlp, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = urlp
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for URLs.
func (u URL) MarshalYAML() (interface{}, error) {
	if u.URL != nil {
		return u.String(), nil
	}
	return nil, nil
}

// Represents a config file, which may have configuration for other programs
// as a top level key.
type configFile struct {
	JWTProxy *Config
}

// Config is the global configuration
type Config struct {
	Signer   *SignerConfig
	Verifier *VerifierConfig
}

type VerifierConfig struct {
	ListenAddr string
	CrtFile    string
	KeyFile    string
	Upstream   URL
}

type SignerConfig struct {
	ListenAddr string
	CAKeyFile  string
	CACrtFile  string
}

// DefaultConfig is a configuration that can be used as a fallback value.
var DefaultConfig = configFile{
	JWTProxy: &Config{
		Signer: &SignerConfig{
			ListenAddr: ":8080",
		},
		Verifier: &VerifierConfig{
			ListenAddr: ":8081",
		},
	},
}

// Load is a shortcut to open a file, read it, and generate a Config.
// It supports relative and absolute paths.
func Load(path string) (config *Config, err error) {
	cFile := &DefaultConfig
	if path == "" {
		err = fmt.Errorf("A configuration file is required")
		return
	}

	f, err := os.Open(os.ExpandEnv(path))
	if err != nil {
		return
	}
	defer f.Close()

	d, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(d, cFile)
	if err != nil {
		return
	}

	config = cFile.JWTProxy
	return
}

// TODO: Integrate me.
type RegistrableComponentConfig struct {
	Type    string      `yaml:"type"`
	Options interface{} `yaml:"options"`
}

func LoadRegistrableConfigOptions(registrableComponentConfig RegistrableComponentConfig, target interface{}) error {
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(bytes, target)
}
