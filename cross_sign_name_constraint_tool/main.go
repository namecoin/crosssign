// Copyright 2018 Jeremy Rand.

// This file is part of crosssignnameconstraint.
//
// crosssignnameconstraint is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// crosssignnameconstraint is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with crosssignnameconstraint.  If not, see
// <https://www.gnu.org/licenses/>.

package main

import (
	"io/ioutil"
	"log"

	"github.com/namecoin/crosssignnameconstraint"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var (
	flagGroup                = cflag.NewGroup(nil, "cert")
	rootCommonNamePrefixFlag = cflag.String(flagGroup,
		"root-cn-prefix", "Namecoin Restricted CKBI Root CA for ",
		"Prefix to apply to the CommonName of the generated root CA")
	intermediateCommonNamePrefixFlag = cflag.String(flagGroup,
		"intermediate-cn-prefix",
		"Namecoin Restricted CKBI Intermediate CA for ",
		"Prefix to apply to the CommonName of the generated "+
			"intermediate CA")
	excludedDomainFlag = cflag.String(flagGroup,
		"excluded-domain", ".bit",
		"Block the input root CA from certifying for this DNS "+
			"domain name.")
	inputCAPathFlag = cflag.String(flagGroup,
		"input-root-ca-path", "", "Path to the input root CA (must "+
			"be in DER format)")
	outputPrefixFlag = cflag.String(flagGroup,
		"output-prefix", "", "Prefix of paths for writing the "+
			"output CA's (will be in DER format)")
)

func main() {
	config := easyconfig.Configurator{
		ProgramName: "cross_sign_name_constraint_tool",
	}
	err := config.Parse(nil)
	if err != nil {
		log.Fatalf("Couldn't parse configuration: %s", err)
	}

	inputCAPath := inputCAPathFlag.Value()

	if inputCAPath == "" {
		log.Fatalf(
			"Missing required --cert.input-root-ca-path parameter")
	}

	inputCADER, err := ioutil.ReadFile(inputCAPath)
	if err != nil {
		log.Fatalf("Couldn't read input CA: %s", err)
	}

	outputRootDER, outputIntermediateDER, outputCrossSignedDER, err :=
		crosssignnameconstraint.GetCrossSignedDER(
			rootCommonNamePrefixFlag.Value(),
			intermediateCommonNamePrefixFlag.Value(),
			excludedDomainFlag.Value(), inputCADER)
	if err != nil {
		log.Fatalf("Couldn't process input CA: %s", err)
	}

	err = ioutil.WriteFile(outputPrefixFlag.Value()+"root.crt",
		outputRootDER, 0600)
	if err != nil {
		log.Fatalf("Couldn't write root CA: %s", err)
	}

	err = ioutil.WriteFile(outputPrefixFlag.Value()+"intermediate.crt",
		outputIntermediateDER, 0600)
	if err != nil {
		log.Fatalf("Couldn't write intermediate CA: %s", err)
	}

	err = ioutil.WriteFile(outputPrefixFlag.Value()+"cross-signed.crt",
		outputCrossSignedDER, 0600)
	if err != nil {
		log.Fatalf("Couldn't write cross-signed CA: %s", err)
	}
}
