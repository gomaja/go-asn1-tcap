package tcap_test

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

func reviewFailure(t *testing.T, input string, opts ...tcap.ParseOption) *tcap.ParseError {
	t.Helper()
	m, err := tcap.Parse(hx(input), opts...)
	var pe *tcap.ParseError
	if m != nil || !errors.As(err, &pe) {
		t.Fatalf("Parse = %T, %v; want nil, *ParseError", m, err)
	}
	return pe
}

func TestReviewF1TransactionBeforePortions(t *testing.T) {
	bad := tlv("6c", hexInvoke, "a103020105")
	dp := dialoguePortion(hexDialogueAS, hexAARQ)
	cases := []struct{ name, input string }{
		{"Continue missing DTID", tlv("65", hexOTID, bad)},
		{"Begin missing OTID", tlv("62", bad)},
		{"End missing DTID", tlv("64", bad)},
		{"Abort components", tlv("67", hexDTID, bad)},
		{"unknown with AARQ", tlv("63", hexOTID, dp)},
		{"unknown with bad component", tlv("63", hexOTID, bad)},
		{"extra after bad component", tlv("62", hexOTID, bad, "4f00")},
		{"long OTID before bad Invoke", "620e480501020304056c05a103020101"},
		{"empty OTID before bad Invoke", tlv("62", "4800", bad)},
		{"wrong order", tlv("65", hexDTID, hexOTID, bad)},
		{"dialogue after components", tlv("62", hexOTID, bad, dp)},
		{"duplicate OTID", tlv("62", hexOTID, hexOTID, bad)},
		{"duplicate DTID", tlv("65", hexOTID, hexDTID, hexDTID, bad)},
		{"duplicate dialogue", tlv("62", hexOTID, dp, dp, bad)},
		{"duplicate components", tlv("62", hexOTID, bad, bad)},
		{"Begin has DTID", tlv("62", hexOTID, hexDTID, bad)},
		{"End has OTID", tlv("64", hexDTID, hexOTID, bad)},
		{"Begin has abort cause", tlv("62", hexOTID, "4a0101", bad)},
		{"Abort two reasons", tlv("67", hexDTID, "4a0101", dp)},
		{"Unidirectional has ID", tlv("61", hexOTID, bad)},
		{"Unidirectional missing components", tlv("61", dp)},
		{"trailing data", tlv("62", hexOTID, bad) + "00"},
		{"malformed outer", "62804804010203046c05a103020101"},
		{"primitive dialogue portion", tlv("62", hexOTID, "4b00", bad)},
		{"primitive component portion", tlv("62", hexOTID, "4c05a103020101")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pe := reviewFailure(t, tc.input)
			if pe.Portion != tcap.PortionTransaction || pe.ComponentIndex != -1 || pe.Dialogue != nil || pe.Components != nil || pe.InvokeID != nil {
				t.Fatalf("transaction context = %+v", pe)
			}
		})
	}
	t.Run("tolerated transaction size", func(t *testing.T) {
		var log ber.ViolationLog
		pe := reviewFailure(t, "620e480501020304056c05a103020101", tcap.WithConstraintTolerance(&log))
		if pe.Portion != tcap.PortionComponent || pe.ComponentIndex != 0 || len(log.Snapshot()) != 0 {
			t.Fatalf("tolerated failure = %+v, reports = %v", pe, log.Snapshot())
		}
	})
	t.Run("Abort with malformed dialogue", func(t *testing.T) {
		pe := reviewFailure(t, tlv("67", hexDTID, "6b022800"))
		if pe.Portion != tcap.PortionDialogue || pe.ComponentIndex != -1 {
			t.Fatalf("Abort dialogue failure = %v", pe)
		}
	})
}

func TestReviewF2DerivableTransactionIDs(t *testing.T) {
	bad := tlv("6c", "a103020105")
	cases := []struct{ name, input, otid, dtid string }{
		{"duplicate DTID", "6509480101490102490103", "01", ""},
		{"duplicate OTID", tlv("62", "480101", "480102", bad), "", ""},
		{"unexpected End OTID", tlv("64", "490102", "480101", bad), "", "02"},
		{"unexpected Begin DTID", tlv("62", "480101", "490102", bad), "01", ""},
		{"misplaced Continue IDs", tlv("65", "490102", "480101", bad), "", ""},
		{"Unidirectional IDs", tlv("61", "480101", "490102", bad), "", ""},
		{"UNKNOWN unique IDs", tlv("63", "4f00", "480101", "490102", bad), "01", "02"},
		{"UNKNOWN duplicate IDs", tlv("63", "480101", "480102", "490103", "490104"), "", ""},
		{"constructed OTID", tlv("62", "680704020102040103", bad), "010203", ""},
		{"indefinite OTID", tlv("62", "6880040201020401030000", bad), "010203", ""},
		{"constructed DTID", tlv("64", "6903040102", bad), "", "02"},
		{"indefinite DTID", tlv("64", "69800401020000", bad), "", "02"},
		{"malformed constructed ID", tlv("62", "6803020101", bad), "", ""},
		{"constructed long ID", tlv("62", "680704050102030405", bad), "", ""},
		{"truncated Begin child", "62074801016c05a103", "01", ""},
		{"truncated Continue child", "650a4801014901026c05a103", "01", "02"},
		{"truncated End child", "64074901026c05a103", "", "02"},
		{"duplicate before truncated child", "620a4801014801026c05a103", "", ""},
		{"truncated duplicate OTID", "6206480101480501", "", ""},
		{"truncated duplicate DTID", "6509480101490102490503", "01", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pe := reviewFailure(t, tc.input)
			if pe.OTID.String() != tc.otid || pe.DTID.String() != tc.dtid {
				t.Fatalf("IDs = %s/%s; want %s/%s", pe.OTID, pe.DTID, tc.otid, tc.dtid)
			}
		})
	}
	for _, id := range []string{"680704020102040103", "6880040201020401030000"} {
		m, err := tcap.Parse(hx(tlv("62", id)))
		if err != nil || m.(*tcap.Begin).OTID.String() != "010203" {
			t.Fatalf("valid constructed OTID = %v, %v", m, err)
		}
	}
}

func TestReviewF3ResourceLimitsAndEmptyContext(t *testing.T) {
	dp := dialoguePortion(hexDialogueAS, hexAARQ)
	pe := reviewFailure(t, tlv("62", hexOTID, dp, "6c00"))
	t.Run("empty component portion", func(t *testing.T) {
		if pe.ComponentIndex != -1 || pe.Dialogue != nil || pe.Components != nil || pe.InvokeID != nil {
			t.Fatalf("empty component portion context = %+v", pe)
		}
	})
	for _, tc := range []struct {
		name, input string
		limits      ber.DecodeLimits
	}{
		{"20 Rejects", tlv("62", "480101", tlv("6c", strings.Repeat("a4050500800100", 20))), ber.DecodeLimits{MaxElements: 30}},
		{"three results", "62144801016c0fa203020100a203020100a203020100", ber.DecodeLimits{MaxElements: 4}},
		{"nested parameter", tlv("62", "480101", tlv("6c", tlv("a1", "020101020101", "30053003020101"))), ber.DecodeLimits{MaxDepth: 2}},
		{"octet-aligned known dialogue", tlv("62", "480101", tlv("6b", tlv("28", hexDialogueAS, tlv("81", tlv("60", hexACN3, tlv("be", strings.Repeat("280506012a8100", 20))))))), ber.DecodeLimits{MaxElements: 30}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pe := reviewFailure(t, tc.input, tcap.WithDecodeLimits(tc.limits))
			if !errors.Is(pe, ber.ErrResourceLimit) || pe.Portion != tcap.PortionTransaction || pe.ComponentIndex != -1 || pe.Dialogue != nil || pe.Components != nil || pe.InvokeID != nil || pe.OTID.String() != "01" {
				t.Fatalf("limited context = %+v, OTID = %s", pe, pe.OTID)
			}
		})
	}
	t.Run("inspection scan limits", func(t *testing.T) {
		// The OTID is the first child, within the scanned prefix, so it stays
		// derivable for the P-Abort of Q.774 (06/97) Table 7. go-asn1 locates
		// a MaxWork failure at the root, which leaves none: https://github.com/gomaja/go-asn1/issues/155.
		for _, limits := range []ber.DecodeLimits{{MaxWork: 8}, {MaxElements: 2}} {
			pe := reviewFailure(t, "62074801014f004e00", tcap.WithDecodeLimits(limits))
			wantID := "01"
			if limits.MaxWork != 0 {
				wantID = ""
			}
			if !errors.Is(pe, ber.ErrResourceLimit) || pe.Portion != tcap.PortionTransaction || pe.ComponentIndex != -1 || pe.OTID.String() != wantID || pe.DTID != nil || pe.Dialogue != nil || pe.Components != nil || pe.InvokeID != nil {
				t.Fatalf("limited immediate scan = %+v, IDs = %s/%s", pe, pe.OTID, pe.DTID)
			}
		}
	})
}

func TestReviewF4OpaqueKnownAbstractSyntax(t *testing.T) {
	for _, arcs := range []runtime.ObjectIdentifier{wire.DialogueAsId(), wire.UniDialogueAsId()} {
		oid, err := tcap.ParseOID(arcs.String())
		if err != nil {
			t.Fatal(err)
		}
		for _, encoding := range []runtime.ExternalEncoding{runtime.ExternalSingleASN1Type, runtime.ExternalOctetAligned, runtime.ExternalArbitrary} {
			t.Run(fmt.Sprintf("%s/%d", oid, encoding), func(t *testing.T) {
				e := tcap.External{DirectReference: oid, Encoding: encoding}
				data := hx(hexAARQ)
				switch encoding {
				case runtime.ExternalSingleASN1Type:
					e.SingleASN1Type = data
				case runtime.ExternalOctetAligned:
					e.OctetAligned = data
				case runtime.ExternalArbitrary:
					e.Arbitrary = runtime.BitString{Bytes: data, BitLength: len(data) * 8}
				}
				_, err := (&tcap.End{DTID: tcap.TransactionID{1}, Dialogue: &tcap.Dialogue{Opaque: &e}}).Marshal()
				var fe *tcap.FieldError
				if !errors.Is(err, tcap.ErrUnexpectedDialoguePDU) || !errors.As(err, &fe) || fe.Path != "Dialogue.Opaque.DirectReference" {
					t.Fatalf("Marshal error = %v", err)
				}
			})
		}
	}
	m := &tcap.Begin{OTID: tcap.TransactionID{1}, Dialogue: &tcap.Dialogue{Opaque: &tcap.External{DirectReference: "1.2", Encoding: runtime.ExternalOctetAligned, OctetAligned: []byte{0x21, 0}}}}
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := tcap.Parse(data)
	if err != nil || !reflect.DeepEqual(m, back) {
		t.Fatalf("other abstract syntax = %v, %v", back, err)
	}
}

func TestReviewF5BitStringBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bits  runtime.BitString
		valid bool
		want  runtime.BitString
	}{
		{"MaxInt", runtime.BitString{Bytes: []byte{0x80}, BitLength: math.MaxInt}, false, runtime.BitString{}},
		{"negative", runtime.BitString{Bytes: []byte{0x80}, BitLength: -1}, false, runtime.BitString{}},
		{"zero", runtime.BitString{Bytes: []byte{0xff}, BitLength: 0}, false, runtime.BitString{}},
		{"short", runtime.BitString{Bytes: []byte{0x80}, BitLength: 9}, false, runtime.BitString{}},
		{"exact", runtime.BitString{Bytes: []byte{0xff}, BitLength: 1}, true, runtime.BitString{Bytes: []byte{0x80}, BitLength: 1}},
		{"long", runtime.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 1}, false, runtime.BitString{}},
	} {
		for _, kind := range []string{"protocol-version", "arbitrary"} {
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				bits := tc.bits
				before := bytes.Clone(bits.Bytes)
				m := &tcap.Begin{OTID: tcap.TransactionID{1}}
				if kind == "protocol-version" {
					m.Dialogue = &tcap.Dialogue{Request: &tcap.AARQ{ProtocolVersion: &bits, ApplicationContextName: "1.2"}}
				} else {
					m.Dialogue = &tcap.Dialogue{Opaque: &tcap.External{DirectReference: "1.2", Encoding: runtime.ExternalArbitrary, Arbitrary: bits}}
				}
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("Marshal panicked: %v", p)
					}
				}()
				data, err := m.Marshal()
				valid := tc.valid && (kind != "protocol-version" || tc.bits.BitLength != 0) && (kind != "arbitrary" || tc.name != "exact")
				if (err == nil) != valid {
					t.Fatalf("Marshal = %x, %v; valid = %t", data, err, valid)
				}
				if !bytes.Equal(bits.Bytes, before) || bits.BitLength != tc.bits.BitLength {
					t.Fatal("Marshal changed BIT STRING")
				}
				if !valid {
					return
				}
				back, err := tcap.Parse(data)
				if err != nil {
					t.Fatal(err)
				}
				var got runtime.BitString
				if kind == "protocol-version" {
					got = *back.(*tcap.Begin).Dialogue.Request.ProtocolVersion
				} else {
					got = back.(*tcap.Begin).Dialogue.Opaque.Arbitrary
				}
				if got.BitLength != tc.want.BitLength || !bytes.Equal(got.Bytes, tc.want.Bytes) {
					t.Fatalf("parsed bits = %+v; want %+v", got, tc.want)
				}
			})
		}
	}
	for _, tc := range []struct{ name, input string }{
		{"zero protocol-version", tlv("62", "480101", dialoguePortion(hexDialogueAS, "6008800100a10306012a"))},
		{"short protocol-version", tlv("62", "480101", dialoguePortion(hexDialogueAS, "600980020880a10306012a"))},
		{"short arbitrary", tlv("62", "480101", tlv("6b", "280706012a82020880"))},
	} {
		t.Run("Parse/"+tc.name, func(t *testing.T) {
			m, err := tcap.Parse(hx(tc.input))
			if tc.name == "zero protocol-version" {
				if err != nil || m.(*tcap.Begin).Dialogue.Request.ProtocolVersion.BitLength != 0 {
					t.Fatalf("Parse = %v, %v", m, err)
				}
			} else if err == nil {
				t.Fatal("Parse accepted invalid unused-bit count")
			}
		})
	}
}

func TestReviewF6ParameterBERStructure(t *testing.T) {
	for _, tc := range []struct {
		input string
		valid bool
	}{
		{"2100", false}, {"300102", false}, {"3003020101", true},
		{"048101aa", true}, {"24800401aa0000", true},
	} {
		for _, kind := range []string{"Invoke", "ReturnError", "Result", "ResultNotLast", "SingleASN1Type", "UserInformation", "OctetAligned"} {
			t.Run(tc.input+"/"+kind, func(t *testing.T) {
				data := hx(tc.input)
				m := &tcap.Begin{OTID: tcap.TransactionID{1}}
				switch kind {
				case "Invoke":
					m.Components = []tcap.Component{{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.LocalCode(1), Parameter: data}}}
				case "ReturnError":
					m.Components = []tcap.Component{{ReturnError: &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.LocalCode(1), Parameter: data}}}
				case "Result":
					m.Components = []tcap.Component{{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(1), Parameter: data}}}}
				case "ResultNotLast":
					m.Components = []tcap.Component{{ReturnResultNotLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(1), Parameter: data}}}}
				case "SingleASN1Type":
					m.Dialogue = &tcap.Dialogue{Opaque: &tcap.External{DirectReference: "1.2", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: data}}
				case "OctetAligned":
					m.Dialogue = &tcap.Dialogue{Opaque: &tcap.External{DirectReference: "1.2", Encoding: runtime.ExternalOctetAligned, OctetAligned: data}}
				case "UserInformation":
					m.Dialogue = &tcap.Dialogue{Request: &tcap.AARQ{ApplicationContextName: "1.2", UserInformation: []tcap.External{{DirectReference: "1.2", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: data}}}}
				}
				out, err := m.Marshal()
				valid := tc.valid || kind == "OctetAligned"
				if valid {
					if err != nil {
						t.Fatal(err)
					}
					back, err := tcap.Parse(out)
					if err != nil || !reflect.DeepEqual(m, back) {
						t.Fatalf("round trip = %v, %v", back, err)
					}
				} else if expected := ber.ValidateBEREncodedElement(data); expected == nil || err == nil || !sameElementFailure(err, expected) {
					t.Fatalf("Marshal = %x, %v; want codec BER element failure", out, err)
				}
			})
		}
	}
}

func TestReviewF6ParameterBeyondDefaultDecodeDepth(t *testing.T) {
	parameter := "020101"
	for range 130 {
		parameter = tlv("30", parameter)
	}
	input := tlv("62", "480101", tlv("6c", tlv("a1", "020101020101", parameter)))
	m, err := tcap.Parse(hx(input), tcap.WithDecodeLimits(ber.DecodeLimits{MaxDepth: 256}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Marshal()
	if err != nil || !bytes.Equal(out, hx(input)) {
		t.Fatalf("Marshal under raised decode limits = %x, %v", out, err)
	}
}

func TestReviewF7KnownDialoguePDUTags(t *testing.T) {
	for _, as := range []string{hexDialogueAS, hexUniAS} {
		for _, pdu := range []string{"6000", "6100", "6200", "6300", "6400", "6500", "4000", "3000", "a000"} {
			t.Run(as+"/"+pdu, func(t *testing.T) {
				pe := reviewFailure(t, tlv("62", "480101", dialoguePortion(as, pdu)))
				known := pdu == "6000" || as == hexDialogueAS && (pdu == "6100" || pdu == "6400")
				if pe.Portion != tcap.PortionDialogue || errors.Is(pe, tcap.ErrUnexpectedDialoguePDU) == known {
					t.Fatalf("PDU classification = %v; recognized = %t", pe, known)
				}
			})
		}
	}
}

func TestReviewF10InvalidOptionsBeforeData(t *testing.T) {
	for _, opt := range []tcap.ParseOption{
		nil, tcap.WithConstraintTolerance(nil),
		tcap.WithDecodeLimits(ber.DecodeLimits{MaxDepth: -1}),
		tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: -1}),
		tcap.WithDecodeLimits(ber.DecodeLimits{MaxWork: -1}),
		tcap.WithDecodeLimits(ber.DecodeLimits{MaxRealDecimalDigits: -1}),
	} {
		for _, data := range [][]byte{nil, {0xff}, hx("6203480101")} {
			m, err := tcap.Parse(data, opt)
			var pe *tcap.ParseError
			if m != nil || !errors.Is(err, tcap.ErrInvalidParseOption) || errors.As(err, &pe) {
				t.Errorf("Parse(%x, %v) = %v, %v; want invalid option outside ParseError", data, opt, m, err)
			}
		}
	}
	var log ber.ViolationLog
	for _, limits := range []ber.DecodeLimits{{}, {MaxWork: 1}, {MaxDepth: math.MaxInt, MaxElements: math.MaxInt, MaxWork: math.MaxInt}} {
		_, err := tcap.Parse(nil, tcap.WithDecodeLimits(limits), tcap.WithConstraintTolerance(&log))
		if !errors.Is(err, tcap.ErrEmptyData) || len(log.Snapshot()) != 0 {
			t.Fatalf("valid options with empty input = %v, reports = %v", err, log.Snapshot())
		}
	}
}

func TestReviewF11SingleLineParseErrors(t *testing.T) {
	pe := reviewFailure(t, tlv("63", "480101"))
	var causes interface{ Unwrap() []error }
	if strings.ContainsAny(pe.Error(), "\r\n") || !strings.Contains(pe.Error(), "; ") || !errors.Is(pe, tcap.ErrUnrecognizedMessageType) || !errors.As(pe, &causes) || len(causes.Unwrap()) != 2 {
		t.Fatalf("joined error = %q, sentinel match = %t", pe.Error(), errors.Is(pe, tcap.ErrUnrecognizedMessageType))
	}
	if !errors.Is(pe, causes.Unwrap()[0]) || !errors.Is(pe, causes.Unwrap()[1]) {
		t.Fatal("joined causes are unreachable")
	}
	// A failing component is the only cause of a component portion failure.
	pe = reviewFailure(t, tlv("62", "480101", "6c05a903020101"))
	if strings.ContainsAny(pe.Error(), "\r\n") || pe.Err != tcap.ErrUnrecognizedComponent {
		t.Fatalf("component error = %q", pe.Error())
	}
}

// Q.774 (06/97) Table 7 distinguishes an unrecognized message type from a
// badly formatted transaction portion, also when the message is truncated.
func TestParseKeepsUnrecognizedTypeWhenTruncated(t *testing.T) {
	for _, input := range []string{"6305480101", "638048010100"} {
		pe := reviewFailure(t, input)
		if !errors.Is(pe, tcap.ErrUnrecognizedMessageType) || !errors.Is(pe, ber.ErrTruncated) || pe.OTID.String() != "01" {
			t.Fatalf("%s: %v, OTID %s", input, pe, pe.OTID)
		}
	}
}

func TestReviewF12FailingComponentType(t *testing.T) {
	for _, tc := range []struct {
		tag  string
		want tcap.ComponentType
	}{
		{"a1", tcap.ComponentTypeInvoke}, {"a2", tcap.ComponentTypeReturnResultLast}, {"a3", tcap.ComponentTypeReturnError},
		{"a4", tcap.ComponentTypeReject}, {"a7", tcap.ComponentTypeReturnResultNotLast}, {"a9", ""}, {"81", ""},
	} {
		t.Run("codec/"+string(tc.want)+tc.tag, func(t *testing.T) {
			pe := reviewFailure(t, tlv("62", "480101", tlv("6c", tlv(tc.tag))))
			reviewComponentType(t, pe, tc.want)
		})
	}
	for _, tc := range []struct {
		input string
		want  tcap.ComponentType
	}{
		{"a1050500020101", tcap.ComponentTypeInvoke}, {"a2020500", tcap.ComponentTypeReturnResultLast},
		{"a3050500020101", tcap.ComponentTypeReturnError}, {"a409020200808003020101", tcap.ComponentTypeReject},
		{"a7020500", tcap.ComponentTypeReturnResultNotLast},
	} {
		t.Run("receiver/"+string(tc.want), func(t *testing.T) {
			pe := reviewFailure(t, tlv("62", "480101", tlv("6c", tc.input)))
			reviewComponentType(t, pe, tc.want)
		})
	}
	t.Run("truncated Reject", func(t *testing.T) {
		pe := reviewFailure(t, tlv("62", "480101", "6c03a40302"))
		reviewComponentType(t, pe, tcap.ComponentTypeReject)
	})
	for _, input := range []string{"6203480101ff", "62054801016c00", tlv("62", tlv("6c", "a400"))} {
		pe := reviewFailure(t, input)
		if pe.ComponentIndex != -1 {
			t.Fatalf("ComponentIndex = %d", pe.ComponentIndex)
		}
		reviewComponentType(t, pe, "")
	}
}

func reviewComponentType(t *testing.T, pe *tcap.ParseError, want tcap.ComponentType) {
	t.Helper()
	if pe.ComponentType != want {
		t.Fatalf("ComponentType = %q; want %q, error = %v", pe.ComponentType, want, pe)
	}
}

// Compare the location and cause that the codec exposes for open-type bytes.
func sameElementFailure(got, want error) bool {
	var g, w *ber.ElementError
	if !errors.As(got, &g) || !errors.As(want, &w) {
		return false
	}
	if g.Offset() != w.Offset() || !reflect.DeepEqual(g.ChildIndexes(), w.ChildIndexes()) {
		return false
	}
	for _, cause := range []error{ber.ErrInvalidTag, ber.ErrInvalidLength, ber.ErrInvalidValue, ber.ErrExtraData, ber.ErrTruncated} {
		if errors.Is(want, cause) {
			return errors.Is(got, cause)
		}
	}
	return false
}
