package crosssignnameconstraint_test

import (
	"io/ioutil"
	"testing"

	"github.com/namecoin/crosssignnameconstraint"
)

func TestGo19xASN1UnmarshalBug(t *testing.T) {
	rootCommonNamePrefix := "Root CA for "
	intermediateCommonNamePrefix := "Intermediate CA for "
	excludedDomain := ".bit"

	inputCAPath := "./test/asn1_testcase_1.crt"
	inputCADER, err := ioutil.ReadFile(inputCAPath)
	if err != nil {
		t.Error("Couldn't read input CA:", err)
	}

	_, _, _, err =
		crosssignnameconstraint.GetCrossSignedDER(
			rootCommonNamePrefix, intermediateCommonNamePrefix,
			excludedDomain, inputCADER)
	if err != nil {
		t.Error("Couldn't process input CA.  If you're using Go "+
			"1.10.0 or higher, this indicates a possible "+
			"regression for "+
			"https://github.com/namecoin/crosssignnameconstraint/"+
			"issues/2 :", err)
	}
}
