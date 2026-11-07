package tcap_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

func TestOpenValueEncodingValidation(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		is          error
	}{
		{"NULL", "0500", nil},
		{"REAL base two", "0903800001", nil},
		{"EXTERNAL constructed single-ASN1-type", "280706012aa0020500", nil},
		{"EMBEDDED PDV constructed identification", "2b06a00285008200", nil},
		{"CHARACTER STRING constructed identification", "3d06a00285008200", nil},
		// ITU-T X.690 (02/2021) clause 8.5.7.2 reserves REAL base bits 11.
		{"REAL reserved base", "0903b00001", ber.ErrInvalidValue},
		// ITU-T X.690 (02/2021) clause 8.18.1 tags an EXTERNAL's
		// single-ASN1-type [0] explicitly, so it must be constructed
		// (clause 8.14.3).
		{"EXTERNAL primitive single-ASN1-type", "280706012a80020500", ber.ErrInvalidTag},
		// ITU-T X.680 (02/2021) clauses 36.5 and 44.5 tag identification
		// [0], a CHOICE, explicitly (clause 31.2.7 c), so it must be
		// constructed (ITU-T X.690 (02/2021) clauses 8.14.3, 8.17.1 and
		// 8.24.1). The data value is [2].
		{"EMBEDDED PDV primitive identification", "2b06800285008200", ber.ErrInvalidTag},
		{"CHARACTER STRING primitive identification", "3d06800285008200", ber.ErrInvalidTag},
		// The contents octets of that [0] are the complete base encoding
		// (ITU-T X.690 (02/2021) clause 8.14.3), so it holds exactly one
		// value. In the indefinite form, the contents octets end at the
		// end-of-contents octets (clause 8.1.3.6).
		{"EXTERNAL empty single-ASN1-type", "280506012aa000", ber.ErrUnexpectedElement},
		{"EXTERNAL doubled single-ASN1-type", "280906012aa00405000500", ber.ErrUnexpectedElement},
		{"EXTERNAL indefinite empty single-ASN1-type", "280706012aa0800000", ber.ErrUnexpectedElement},
		{"EXTERNAL indefinite doubled single-ASN1-type", "280b06012aa080050005000000", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV empty identification", "2b04a0008200", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV doubled identification", "2b08a004850085008200", ber.ErrUnexpectedElement},
		{"CHARACTER STRING empty identification", "3d04a0008200", ber.ErrUnexpectedElement},
		{"CHARACTER STRING doubled identification", "3d08a004850085008200", ber.ErrUnexpectedElement},
		// ITU-T X.690 (02/2021) clauses 8.17.1, 8.18.1 and 8.24.1 fix the
		// components of an EXTERNAL, EMBEDDED PDV and CHARACTER STRING and
		// their order; ITU-T X.680 (02/2021) clauses 36.5 and 44.5 list the
		// identification alternatives. Their implicit tags give their base
		// types (X.690 clause 8.14.4), including a constructed OCTET STRING
		// (clause 8.7.1).
		{"EXTERNAL indirect reference", "2807020101a0020500", nil},
		{"EXTERNAL direct and indirect references and descriptor", "280d06012a020101070141a0020500", nil},
		{"EXTERNAL octet-aligned", "280606012a810141", nil},
		{"EXTERNAL constructed octet-aligned", "280906012aa1040402abcd", nil},
		{"EXTERNAL arbitrary", "280706012a82020780", nil},
		{"EXTERNAL constructed arbitrary", "280906012aa20403020080", nil},
		{"EMBEDDED PDV syntaxes", "2b0ca008a00680012a81012a8200", nil},
		{"EMBEDDED PDV context-negotiation", "2b0ca008a30680010181012a8200", nil},
		{"EMBEDDED PDV constructed data value", "2b0aa0028500a2040402abcd", nil},
		{"CHARACTER STRING syntax", "3d0aa00381012a8203414243", nil},
		{"EXTERNAL indefinite", "288006012aa00205000000", nil},
		{"EMBEDDED PDV indefinite", "2b80a0808500000082000000", nil},
		// X.690 clause 8.18.4, Table 2: the identification of an EXTERNAL is
		// syntax, presentation-context-id or context-negotiation, so a
		// direct or an indirect reference is present.
		{"EXTERNAL without reference", "2804a0020500", ber.ErrInvalidValue},
		{"EXTERNAL descriptor without reference", "2807070164a0020500", ber.ErrInvalidValue},
		{"EXTERNAL octet-aligned without reference", "2803810141", ber.ErrInvalidValue},
		{"EXTERNAL arbitrary without reference", "280482020780", ber.ErrInvalidValue},
		{"EXTERNAL indefinite without reference", "2880a00205000000", ber.ErrInvalidValue},
		{"EXTERNAL without reference in a SEQUENCE", "30062804a0020500", ber.ErrInvalidValue},
		// A component that is missing, repeated or out of its order is an
		// element out of place (X.690 clause 8.9.2).
		{"EXTERNAL without encoding", "280306012a", ber.ErrUnexpectedElement},
		{"EXTERNAL reference after descriptor", "280906012a07014106012a", ber.ErrUnexpectedElement},
		{"EXTERNAL repeated direct reference", "280a06012a06012aa0020500", ber.ErrUnexpectedElement},
		{"EXTERNAL repeated indirect reference", "280a020101020101a0020500", ber.ErrUnexpectedElement},
		{"EXTERNAL indirect reference before direct", "280a02010106012aa0020500", ber.ErrUnexpectedElement},
		{"EXTERNAL two encodings", "280b06012aa0020500a0020500", ber.ErrUnexpectedElement},
		{"EXTERNAL encoding [3]", "280506012a8300", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV without data value", "2b07a00581032a0304", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV repeated data value", "2b0ba00581032a030482008200", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV element between identification and data value", "2b0ba00581032a030481008200", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV identification [6]", "2b06a00286008200", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV empty syntaxes", "2b06a002a0008200", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV reversed syntaxes", "2b0ca008a00681012a80012a8200", ber.ErrUnexpectedElement},
		{"CHARACTER STRING without data value", "3d07a00581032a0304", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV indefinite without data value", "2b80a080850000000000", ber.ErrUnexpectedElement},
		{"EMBEDDED PDV without data value in an EXTERNAL", "280e06012aa0092b07a00581032a0304", ber.ErrUnexpectedElement},
		// The form and contents of an identification alternative are those
		// of its base type (X.690 clause 8.14.4): a primitive, minimal INTEGER
		// (clauses 8.3.1 and 8.3.2) or a primitive, empty NULL (clauses 8.8.1
		// and 8.8.2). An arbitrary encoding is a BIT STRING, whose initial
		// octet is present and below 8 (clause 8.6.2.2).
		{"EMBEDDED PDV non-minimal presentation-context-id", "2b08a004820200018200", ber.ErrInvalidValue},
		{"EMBEDDED PDV fixed identification with contents", "2b07a0038501008200", ber.ErrInvalidValue},
		{"CHARACTER STRING non-minimal presentation-context-id", "3d08a004820200018200", ber.ErrInvalidValue},
		{"EMBEDDED PDV empty presentation-context-id", "2b06a00282008200", ber.ErrInvalidValue},
		{"EMBEDDED PDV non-minimal context-negotiation", "2b0da009a3078002000181012a8200", ber.ErrInvalidValue},
		{"EMBEDDED PDV constructed presentation-context-id", "2b06a002a2008200", ber.ErrInvalidTag},
		{"EMBEDDED PDV constructed fixed identification", "2b06a002a5008200", ber.ErrInvalidTag},
		{"EXTERNAL arbitrary without initial octet", "280506012a8200", ber.ErrInvalidValue},
		{"EXTERNAL arbitrary with 8 unused bits", "280706012a82020800", ber.ErrInvalidValue},
		// The segments of a constructed octet-aligned or arbitrary encoding
		// are OCTET STRING or BIT STRING encodings (X.690 clauses 8.7.3 and
		// 8.6.4.1), and only the last segment of a BIT STRING ends short of
		// an octet (clause 8.6.4).
		{"EXTERNAL constructed octet-aligned with NULL segment", "280706012aa1020500", ber.ErrInvalidTag},
		{"EXTERNAL constructed arbitrary with unused bits before the last segment", "280d06012aa2080302018003020080", ber.ErrInvalidValue},
		// X.690 clause 8.23.3 encodes a character string as an OCTET STRING,
		// so a constructed one is checked as its whole value (clause
		// 8.7.3.1). Clauses 8.23.7 and 8.23.8 encode UniversalString and
		// BMPString in 4-octet and 2-octet values. X.680 clause 41 with
		// Tables 8 to 10 gives the characters of NumericString,
		// PrintableString, IA5String and VisibleString, and clauses 46.3 and
		// 47.3 give the forms of GeneralizedTime and UTCTime.
		{"BMPString", "1e020041", nil},
		{"BMPString split across segments", "3e06040100040141", nil},
		{"UniversalString", "1c0400000041", nil},
		{"NumericString", "12053132203334", nil},
		{"PrintableString", "130f416131202728292b2c2d2e2f3a3d3f", nil},
		{"IA5String", "1603417f00", nil},
		{"VisibleString", "1a03207e41", nil},
		{"UTCTime", "170d3236313130373132303030305a", nil},
		{"GeneralizedTime with a fraction", "181332303236313130373132303030302e3132335a", nil},
		{"UniversalString split across segments", "3c080403000000040141", nil},
		{"indefinite BMPString", "3e800401000401410000", nil},
		{"BMPString with a nested segment", "3e082406040100040141", nil},
		{"BMPString of one octet", "1e0100", ber.ErrInvalidValue},
		{"BMPString of three octets", "1e03004100", ber.ErrInvalidValue},
		{"BMPString lone surrogate", "1e02d800", ber.ErrInvalidValue},
		{"constructed BMPString of one octet", "3e03040100", ber.ErrInvalidValue},
		{"UniversalString of three octets", "1c03000000", ber.ErrInvalidValue},
		{"UniversalString above U+10FFFF", "1c0400110000", ber.ErrInvalidValue},
		{"NumericString letter", "120141", ber.ErrInvalidValue},
		{"constructed NumericString with a letter in its second segment", "3206040131040141", ber.ErrInvalidValue},
		{"PrintableString exclamation mark", "130121", ber.ErrInvalidValue},
		{"IA5String octet above 7F", "1601ff", ber.ErrInvalidValue},
		{"VisibleString control character", "1a011f", ber.ErrInvalidValue},
		{"UTCTime month 13", "170d3236313330353132303030305a", ber.ErrInvalidValue},
		{"UTCTime second 60", "170d3236313130373132303036305a", ber.ErrInvalidValue},
		{"GeneralizedTime not a time", "1801ff", ber.ErrInvalidValue},
		{"UniversalString surrogate", "1c040000d800", ber.ErrInvalidValue},
		{"BMPString surrogate pair", "1e04d800dc00", ber.ErrInvalidValue},
		{"constructed BMPString with a nested segment of one octet", "3e052403040100", ber.ErrInvalidValue},
		{"GeneralizedTime 29 February of a common year", "180b323032363032323931325a", ber.ErrInvalidValue},
		{"UTCTime 30 February", "170b303030323330313230305a", ber.ErrInvalidValue},
		{"UTCTime offset without minutes", "170d323631313037313230302b3035", ber.ErrInvalidValue},
	} {
		for _, kind := range []string{"Invoke", "ReturnError", "Result", "ResultNotLast", "UserInformation", "Opaque"} {
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				message, input := openValueMessage(kind, tc.value)
				out, err := message.Marshal()
				if tc.is == nil {
					if err != nil || !bytes.Equal(out, hx(input)) {
						t.Fatalf("Marshal = %x, %v; want %s", out, err, input)
					}
				} else if out != nil || !errors.Is(err, tc.is) {
					t.Fatalf("Marshal = %x, %v; want %v", out, err, tc.is)
				}
				for _, tolerant := range []bool{false, true} {
					var opts []tcap.ParseOption
					var log tcap.ViolationLog
					if tolerant {
						opts = append(opts, tcap.WithTolerance(&log))
					}
					got, err := tcap.Parse(hx(input), opts...)
					if tc.is == nil {
						if err != nil || got == nil {
							t.Fatalf("Parse tolerant=%t = %v, %v", tolerant, got, err)
						}
						back, err := got.Marshal()
						if err != nil || !bytes.Equal(back, out) {
							t.Fatalf("round trip tolerant=%t = %x, %v; want %x", tolerant, back, err, out)
						}
					} else {
						var pe *tcap.ParseError
						if got != nil || !errors.Is(err, tc.is) || !errors.As(err, &pe) {
							t.Fatalf("Parse tolerant=%t = %v, %v; want %v", tolerant, got, err, tc.is)
						}
						portion := tcap.PortionComponent
						if kind == "UserInformation" || kind == "Opaque" {
							portion = tcap.PortionDialogue
						}
						if pe.Portion != portion {
							t.Fatalf("Portion tolerant=%t = %s; want %s", tolerant, pe.Portion, portion)
						}
					}
					if len(log.Snapshot()) != 0 {
						t.Fatal("Parse published violations")
					}
				}
			})
		}
	}
}

func openValueMessage(kind, value string) (tcap.Message, string) {
	data := hx(value)
	e := tcap.External{DirectReference: "1.2", Encoding: tcap.ExternalSingleASN1Type, SingleASN1Type: data}
	external := tlv("28", "06012a", tlv("a0", value))
	if kind == "Opaque" {
		return &tcap.End{DTID: tcap.TransactionID{1}, Dialogue: &tcap.Dialogue{Opaque: &e}},
			tlv("64", "490101", tlv("6b", external))
	}
	m := &tcap.Begin{OTID: tcap.TransactionID{1}}
	if kind == "UserInformation" {
		m.Dialogue = &tcap.Dialogue{Request: &tcap.AARQ{ApplicationContextName: "1.2", UserInformation: []tcap.External{e}}}
		return m, tlv("62", "480101", dialoguePortion(hexDialogueAS, tlv("60", tlv("a1", "06012a"), tlv("be", external))))
	}
	var c tcap.Component
	var component string
	switch kind {
	case "Invoke":
		c.Invoke = &tcap.Invoke{InvokeID: 1, OpCode: tcap.LocalCode(1), Parameter: data}
		component = tlv("a1", "020101020101", value)
	case "ReturnError":
		c.ReturnError = &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.LocalCode(1), Parameter: data}
		component = tlv("a3", "020101020101", value)
	case "Result", "ResultNotLast":
		r := &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(1), Parameter: data}}
		tag := "a2"
		if kind == "Result" {
			c.ReturnResultLast = r
		} else {
			c.ReturnResultNotLast = r
			tag = "a7"
		}
		component = tlv(tag, "020101", tlv("30", "020101", value))
	}
	m.Components = []tcap.Component{c}
	return m, tlv("62", "480101", tlv("6c", component))
}
