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
