package tcap

import (
	"math/big"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
)

// Dialogue is the dialogue portion of a message (ITU-T Q.773 (06/97) clauses
// 3.2 and 4.2.3). Exactly one field is set.
//
// Request, Response and Abort are the structured dialogue PDUs, carried under
// dialogue-as-id; Unidirectional is the unstructured dialogue PDU, carried
// under uniDialogue-as-id. Opaque is a dialogue portion in any other abstract
// syntax: user information that the TC-user defines. Marshal rejects Opaque
// with dialogue-as-id or uniDialogue-as-id; use the corresponding PDU field
// so that the sender rules apply (Q.773 clause 4.2.3).
//
// The dialogue PDUs a message may carry are those of ITU-T Q.774 (06/97)
// Table 3, which this package applies in both Parse modes and in Marshal: an
// AARQ in a Begin (Figure A.5, sheet 3); an AARE with result accepted in a
// Continue or an End (Figure A.5, sheet 7); an AARE with result
// reject-permanent, or an ABRT, in an Abort (Table 3, Note 3; clauses 3.2.1.2
// and 3.2.3). Opaque is allowed in a Continue or an End (clause 3.2.1.2) and
// in an Abort (Q.773 clause 3.1, DialoguePortion comment), not in a Begin.
// The codec requires the AUDT in a Unidirectional (Q.773 clause 4.2.3); under
// WithTolerance, Parse accepts Opaque there and records the violation, and
// Marshal refuses it.
//
// This package also checks dialogue versions (Q.774 clause 3.2.3): Marshal
// requires an AARQ or an AUDT to offer version1, and both Parse modes and
// Marshal require an AARE to select only version1. The versions of a
// received AARQ or AUDT are left to the stack to answer.
type Dialogue struct {
	Request        *AARQ
	Response       *AARE
	Abort          *ABRT
	Unidirectional *AUDT
	Opaque         *External
}

// AARQ is the dialogue request APDU (Q.773 clause 3.2.1, AARQ-apdu).
//
// A nil ProtocolVersion is omitted and means the DEFAULT {version1}.
// A non-nil value is encoded, including ProtocolVersion1() (ITU-T X.690
// (02/2021) clause 8.9.3).
// A nil UserInformation omits the field; a non-nil empty slice encodes an
// empty sequence.
type AARQ struct {
	ProtocolVersion        *runtime.BitString
	ApplicationContextName OID
	UserInformation        []External
}

// AARE is the dialogue response APDU (Q.773 clause 3.2.1, AARE-apdu). The
// zero value of Result is accepted. A nil ProtocolVersion is omitted and
// means the DEFAULT {version1}; a non-nil value is encoded (ITU-T X.690
// (02/2021) clause 8.9.3).
type AARE struct {
	ProtocolVersion        *runtime.BitString
	ApplicationContextName OID
	Result                 wire.AssociateResult
	ResultSourceDiagnostic ResultSourceDiagnostic
	UserInformation        []External
}

// ResultSourceDiagnostic is the result-source-diagnostic of an AARE. Exactly
// one field is set.
type ResultSourceDiagnostic struct {
	DialogueServiceUser     *wire.AssociateSourceDiagnosticDialogueServiceUserValue
	DialogueServiceProvider *wire.AssociateSourceDiagnosticDialogueServiceProviderValue
}

// ABRT is the dialogue abort APDU (Q.773 clause 3.2.1, ABRT-apdu). The zero
// value of AbortSource is dialogue-service-user.
type ABRT struct {
	AbortSource     wire.ABRTSource
	UserInformation []External
}

// AUDT is the unidirectional dialogue APDU (Q.773 clause 3.2.2, AUDT-apdu).
// A nil ProtocolVersion is omitted and means the DEFAULT {version1}; a
// non-nil value is encoded (ITU-T X.690 (02/2021) clause 8.9.3).
type AUDT struct {
	ProtocolVersion        *runtime.BitString
	ApplicationContextName OID
	UserInformation        []External
}

// External is an EXTERNAL value (ITU-T X.690 (02/2021) clause 8.18): one
// element of dialogue user information, or an Opaque dialogue portion.
//
// Encoding selects which of SingleASN1Type, OctetAligned and Arbitrary holds
// the data value; the other two are empty. SingleASN1Type is the complete BER
// encoding of one value, including its tag and length. The data value is in
// the TC-user's syntax: SingleASN1Type keeps the bytes it was given or
// received and is checked only for well-formed BER, and OctetAligned and
// Arbitrary are not checked. Q.773 clause 4.1.1 covers the encoding headers.
type External struct {
	DirectReference     OID
	IndirectReference   *big.Int
	DataValueDescriptor *string

	Encoding       runtime.ExternalEncoding
	SingleASN1Type []byte
	OctetAligned   []byte
	Arbitrary      runtime.BitString
}

// ProtocolVersion1 returns a new BitString containing {version1}, the only
// version defined by ITU-T Q.773 (06/97) clause 3.2. Marshal encodes it as
// 80 02 07 80 in AARQ, AARE and AUDT. A nil ProtocolVersion omits the field
// and means the same version.
func ProtocolVersion1() *runtime.BitString {
	return &runtime.BitString{Bytes: []byte{0x80}, BitLength: 1}
}

// OffersVersion1 reports whether the protocol-version of an AARQ or an AUDT
// includes version1: the field is nil, so it takes its DEFAULT {version1},
// or bit 0 is set. Other bits, including trailing zero bits, do not change
// the result. An empty BitString does not offer version1. A dialogue request
// that does not offer version1 is answered as described in ITU-T Q.774 (06/97)
// clause 3.2.3. OffersVersion1 does not validate the BitString.
func OffersVersion1(protocolVersion *runtime.BitString) bool {
	return protocolVersion == nil || protocolVersion.BitLength >= 1 && len(protocolVersion.Bytes) != 0 && protocolVersion.Bytes[0]&0x80 != 0
}
