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

package crosssignnameconstraint

import (
	"fmt"
)

// TODO: support more general name constraints than just a single excluded DNS
// domain.

// GetCrossSignedDER generates and returns a root CA, intermediate CA,
// cross-signed CA, and error.  The root CA and intermediate CA have a Subject
// CommonName obtained by prepending rootCommonNamePrefix and
// intermediateCommonNamePrefix to the Subject CommonName in the certificate
// encoded in originalDERBytes.  The intermediate CA is signed by the root CA,
// and has a name constraint DNS name exclusion of excludedDomain.  The
// cross-signed CA is signed by the intermediate CA, but is otherwise identical
// to the certificate encoded in originalDERBytes.
func GetCrossSignedDER(rootCommonNamePrefix string,
	intermediateCommonNamePrefix string, excludedDomain string,
	originalDERBytes []byte) ([]byte, []byte, []byte, error) {
	root, rootPriv, err := generateRootCA(rootCommonNamePrefix, originalDERBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error generating root CA: %s", err)
	}

	intermediate, intermediatePriv, err := generateIntermediateCA(
		intermediateCommonNamePrefix, excludedDomain, originalDERBytes,
		root, rootPriv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error generating intermediate CA: %s", err)
	}

	crossSigned, err := generateCrossSignedCA(originalDERBytes,
		intermediate, intermediatePriv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error generating cross-signed CA: %s", err)
	}

	return root, intermediate, crossSigned, nil
}
