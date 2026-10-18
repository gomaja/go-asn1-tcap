package tcap

import wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"

// ITU-T Q.774 (06/97) clauses 3.2.2, 3.3.4 and Table 7 require the IDs
// needed to address an Abort or locate the receiving transaction. The codec
// defines derivability by the IDs it accepted under the active options.
func decodeFailureIDs(pe *ParseError, failure *wire.DecodeError) {
	if failure.Prefix.Otid != nil {
		pe.OTID = append(TransactionID{}, (*failure.Prefix.Otid)...)
	}
	if failure.Prefix.Dtid != nil {
		pe.DTID = append(TransactionID{}, (*failure.Prefix.Dtid)...)
	}
}
