package tcap

import wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"

// ITU-T Q.774 (06/97) clauses 3.2.2, 3.3.4 and Table 7 require the IDs
// needed to address an Abort or locate the receiving transaction. Table 7
// leaves derivability to the implementation: start from the codec's accepted
// Prefix, but suppress an ID whose immediate tag repeats within the bounded
// inspection scan. An ambiguous Abort could end an unrelated peer transaction.
// A codec decode-limit failure skips that scan and leaves both counts zero.
func decodeFailureIDs(pe *ParseError, failure *wire.DecodeError, idCount [2]int) {
	if failure.Prefix.Otid != nil && idCount[0] < 2 {
		pe.OTID = append(TransactionID{}, (*failure.Prefix.Otid)...)
	}
	if failure.Prefix.Dtid != nil && idCount[1] < 2 {
		pe.DTID = append(TransactionID{}, (*failure.Prefix.Dtid)...)
	}
}
