// Copyright 2018 Jeremy Rand.
//
// Based on https://golang.org/src/crypto/x509/x509.go ,
// Copyright 2009 The Go Authors.

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

package crosssign

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// These are modified from the x509 package; they store any field that isn't
// replaced by cross-signing as an asn1.RawValue.
type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	SerialNumber       *big.Int      // Replaced by cross-signing
	SignatureAlgorithm asn1.RawValue // Replaced by cross-signing
	Issuer             asn1.RawValue // Replaced by cross-signing
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	UniqueId           asn1.RawValue   `asn1:"optional,tag:1"` // nolint: golint
	SubjectUniqueId    asn1.RawValue   `asn1:"optional,tag:2"` // nolint: golint
	Extensions         []asn1.RawValue `asn1:"optional,explicit,tag:3"`
}

// Returns cert, error
// nolint: lll
func CrossSign(toSignDERBytes []byte, signerDERBytes []byte, signerPrivateKey interface{}) ([]byte, error) {
	// Based on x509.ParseCertificate
	var toSignCert certificate
	restToSign, err := asn1.Unmarshal(toSignDERBytes, &toSignCert)
	if err != nil {
		return nil, fmt.Errorf("Couldn't unmarshal certificate to sign: %s", err)
	}
	if len(restToSign) > 0 {
		return nil, fmt.Errorf("Trailing data in certificate to sign: %s", asn1.SyntaxError{Msg: "trailing data"})
	}

	// Based on x509.ParseCertificate
	var signerCertASN1 certificate
	restSigner, err := asn1.Unmarshal(signerDERBytes, &signerCertASN1)
	if err != nil {
		return nil, fmt.Errorf("Couldn't unmarshal signer certificate: %s", err)
	}
	if len(restSigner) > 0 {
		return nil, fmt.Errorf("Trailing data in signer certificate: %s", asn1.SyntaxError{Msg: "trailing data"})
	}

	// Based on CreateCertificate

	key, ok := signerPrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	hashFunc := crypto.SHA256

	c := tbsCertificate{
		Version:            toSignCert.TBSCertificate.Version,
		SerialNumber:       serialNumber,
		SignatureAlgorithm: signerCertASN1.TBSCertificate.SignatureAlgorithm,
		Issuer:             signerCertASN1.TBSCertificate.Subject,
		Validity:           toSignCert.TBSCertificate.Validity,
		Subject:            toSignCert.TBSCertificate.Subject,
		PublicKey:          toSignCert.TBSCertificate.PublicKey,
		Extensions:         toSignCert.TBSCertificate.Extensions,
		// TODO: Look into UniqueId and SubjectUniqueId.
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tbsCertificate: %s", err)
	}

	c.Raw = tbsCertContents

	h := hashFunc.New()
	h.Write(tbsCertContents) // nolint: errcheck, gas, gosec
	digest := h.Sum(nil)

	var signerOpts crypto.SignerOpts // nolint: megacheck
	signerOpts = hashFunc

	var signature []byte
	signature, err = key.Sign(rand.Reader, digest, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cert digest: %s", err)
	}

	outputDER, err := asn1.Marshal(certificate{
		nil,
		c,
		signerCertASN1.SignatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed certificate: %s", err)
	}

	return outputDER, nil
}
