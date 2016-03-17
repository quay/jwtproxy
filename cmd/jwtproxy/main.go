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

package main

import (
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos-inc/hmacproxy/config"
	"github.com/coreos-inc/hmacproxy/jwt"
	"github.com/coreos-inc/hmacproxy/proxy"
)

func main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagConfigPath := flag.String("config", "", "Load configuration from the specified yaml file.")
	flagLogLevel := flag.String("log-level", "info", "Define the logging level.")
	flag.Parse()

	// Load configuration.
	config, err := config.Load(*flagConfigPath)
	if err != nil {
		flag.Usage()
		log.Fatalf("failed to load configuration: %s", err)
	}

	// Initialize logging system.
	level, err := log.ParseLevel(*flagLogLevel)
	if err != nil {
		log.Fatalf("failed to parse the log level: %s", err)
	}
	log.SetLevel(level)

	// Create JWT proxy handlers.
	fwp := jwt.NewJWTSignerHandler()
	rvp := jwt.NewJWTVerifierHandler(config.Verifier.Upstream.URL)

	// Create forward and reverse proxies.
	forwardProxy, err := proxy.NewProxy(fwp, config.Signer.CAKeyFile, config.Signer.CACrtFile)
	if err != nil {
		log.Fatalf("failed to create forward proxy: %s", err)
	}

	reverseProxy, err := proxy.NewReverseProxy(rvp)
	if err != nil {
		log.Fatalf("failed to create reverse proxy: %s", err)
	}

	// Start proxies.
	go func() {
		log.Info("Starting forward proxy")
		log.Fatal(http.ListenAndServe(config.Signer.ListenAddr, forwardProxy))
	}()

	go func() {
		if config.Verifier.CrtFile != "" && config.Verifier.KeyFile != "" {
			log.Info("Starting reverse proxy (TLS Enabled)")
			log.Fatal(http.ListenAndServeTLS(config.Verifier.ListenAddr, config.Verifier.CrtFile, config.Verifier.KeyFile, reverseProxy))

		} else {
			log.Info("Starting reverse proxy (TLS Disabled)")
			go log.Fatal(http.ListenAndServe(config.Verifier.ListenAddr, reverseProxy))
		}
	}()

	waitForSignals(syscall.SIGINT, syscall.SIGTERM)
	// TODO: Graceful stop.
}

func waitForSignals(signals ...os.Signal) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, signals...)
	<-interrupts
}
