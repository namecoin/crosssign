// Copyright 2018 Jeremy Rand.

// This file is part of crosssign.
//
// crosssign is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// crosssign is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with crosssign.  If not, see
// <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/x509"
	"io/ioutil"
	"log"

	"github.com/namecoin/crosssign"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var (
	flagGroup                = cflag.NewGroup(nil, "cert")
	signerKeyPathFlag = cflag.String(flagGroup,
		"signer-key", "", "Path to the signer CA private key (must "+
			"be in DER format; must be an EC key)")
	signerCertPathFlag = cflag.String(flagGroup,
		"signer-cert", "", "Path to the signer CA cert (must "+
			"be in DER format)")
	toSignCertPathFlag = cflag.String(flagGroup,
		"to-sign", "", "Path to the CA cert to sign (must "+
			"be in DER format)")
	outputPrefixFlag = cflag.String(flagGroup,
		"output-prefix", "", "Prefix of paths for writing the "+
			"output CA (will be in DER format)")
)

func main() {
	config := easyconfig.Configurator{
		ProgramName: "cross_sign_tool",
	}
	err := config.Parse(nil)
	if err != nil {
		log.Fatalf("Couldn't parse configuration: %s", err)
	}

	// Read the signer cert...

	signerCertPath := signerCertPathFlag.Value()

	if signerCertPath == "" {
		log.Fatalf(
			"Missing required --cert.signer-cert parameter")
	}

	// #nosec G304
	signerCertDER, err := ioutil.ReadFile(signerCertPath)
	if err != nil {
		log.Fatalf("Couldn't read signer cert: %s", err)
	}

	// Read the cert to sign...

	toSignCertPath := toSignCertPathFlag.Value()

	if toSignCertPath == "" {
		log.Fatalf(
			"Missing required --cert.to-sign parameter")
	}

	// #nosec G304
	toSignCertDER, err := ioutil.ReadFile(toSignCertPath)
	if err != nil {
		log.Fatalf("Couldn't read cert to sign: %s", err)
	}

	// Read the signer private key...

	signerKeyPath := signerKeyPathFlag.Value()

	if signerKeyPath == "" {
		log.Fatalf(
			"Missing required --cert.signer-key parameter")
	}

	// #nosec G304
	signerKeyDER, err := ioutil.ReadFile(signerKeyPath)
	if err != nil {
		log.Fatalf("Couldn't read signer key: %s", err)
	}

	// Parse the signer private key...

	signerKey, err := x509.ParseECPrivateKey(signerKeyDER)
	if err != nil {
		log.Fatalf("Couldn't parse signer key: %s", err)
	}

	// Perform the cross-signing...

	resultDER, err := crosssign.CrossSign(toSignCertDER, signerCertDER, signerKey)
	if err != nil {
		log.Fatalf("Couldn't cross-sign: %s", err)
	}

	// Write the result...

	err = ioutil.WriteFile(outputPrefixFlag.Value()+"cross-signed.crt",
		resultDER, 0600)
	if err != nil {
		log.Fatalf("Couldn't write cross-signed CA: %s", err)
	}
}
