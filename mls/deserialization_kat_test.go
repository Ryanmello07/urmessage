package mls

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/urnetwork/message/syntax"
)

// FAMILY 16, DESERIALIZATION, INSTALLED IN THIS PACKAGE'S MANIFEST.
//
// The comparison is package syntax's, and has been since that package landed:
// [syntax.VerifyDeserializationVector] decodes each published header to the published length with
// the header fully consumed, and encodes the published length back to the published header. What
// was missing is that nothing HERE ran it. This registry is the one place that says which of the
// sixteen families run, and a family verified somewhere the registry cannot see is, as far as gate
// 1 is concerned, a family nothing runs.
//
// So this file is a shim and says so: it registers package syntax's verifier under number 16, and
// it owes the same accounting every other family here owes.
//
// Generate is nil. A header is a function of a length and nothing else, so a generator would be
// the encoder the verify direction already drives.
const deserializationKatFile = "deserialization.json"

// Family 16 is installed here, and 16 is deleted from expectedPendingFamilies in the same commit.
func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   16,
		Verify:   syntax.VerifyDeserializationVector,
		Generate: nil,
	})
}

// deserializationCase is the two published answers of one case, read out of the corpus text by
// this file and not by the verifier it installs.
type deserializationCase struct {
	VlbytesHeader string `json:"vlbytes_header"`
	Length        uint64 `json:"length"`
}

// THE FAMILY'S ACCOUNTING. The corpus publishes no cipher suite, so every case is covered; each
// case is two comparisons, one per direction, against two published answers; and the fourteen
// headers and fourteen lengths are twenty-eight different texts.
func TestDeserializationKat(t *testing.T) {
	tally, entries := newVectorRunTally(t, deserializationKatFile)
	for index, raw := range entries {
		published := deserializationCase{}
		if err := json.Unmarshal(raw, &published); err != nil {
			t.Fatalf("%s case %d does not parse: %v", deserializationKatFile, index, err)
		}
		tally.cover(t)
		syntax.VerifyDeserializationVector(t, raw)
		tally.answer(published.VlbytesHeader)
		tally.answer(strconv.FormatUint(published.Length, 10))
	}
	tally.assertRun(t, 14, 0, 28, 28)
	assertVectorFamilyIsInstalled(t, 16, deserializationKatFile, syntax.VerifyDeserializationVector, nil)
	assertInstalledVerifierRefusesAWrongCase(t, 16, vectorManifest[16])
}
