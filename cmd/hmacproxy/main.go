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

package main

import (
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/coreos-inc/hmacproxy"
	"github.com/coreos-inc/hmacproxy/config"
	"github.com/coreos-inc/hmacproxy/credential"
	_ "github.com/coreos-inc/hmacproxy/credential/singlekey"
)

func main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagConfigPath := flag.String("config", "", "Load configuration from the specified yaml file.")
	flagLogLevel := flag.String("log-level", "info", "Define the logging level.")
	flag.Parse()

	// Load configuration
	proxyConfig, err := config.Load(*flagConfigPath)
	if err != nil {
		flag.Usage()
		log.Fatalf("failed to load configuration: %s", err)
	}

	// Initialize logging system
	level, err := log.ParseLevel(*flagLogLevel)
	if err != nil {
		log.Fatal("failed to parse the log level")
	}
	log.SetLevel(level)

	// Run subsystems.
	// TODO: Ability to disable the one that we don't want to run.
	if proxyConfig.Signer != nil {
		go runSigner(*proxyConfig.Signer)
	}
	if proxyConfig.Verifier != nil {
		go runVerifier(*proxyConfig.Verifier)
	}

	// Wait for interruption.
	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
}

func runSigner(config config.SignerConfig) {
	log.Infof("Starting signing proxy on: %s", config.ListenerAddr)

	signingCredential := credential.Credential{
		config.Key.ID,
		config.Key.Secret,
		config.Key.Service,
		config.Key.Region,
	}

	signingProxy, err := hmacproxy.NewSigningProxy(signingCredential)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.ListenAndServe(config.ListenerAddr, signingProxy))
}

func runVerifier(config config.VerifierConfig) {
	log.Infof(
		"Starting verification proxy listening on: %s with upstream: %v",
		config.ListenerAddr,
		config.Upstream,
	)

	cs, err := credential.NewStore(config.CredentialSource)
	if err != nil {
		log.Fatal(err)
	}

	verificationProxy, err := hmacproxy.NewVerifyingProxy(
		config.Upstream.URL,
		cs,
		config.MaxClockSkew,
	)

	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.ListenAndServe(config.ListenerAddr, verificationProxy))
}

func waitForSignals(signals ...os.Signal) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, signals...)
	<-interrupts
}
