package tcap_test

import (
	"errors"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func TestReview4UnidirectionalAAREMarshal(t *testing.T) {
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("Marshal panicked: %v", value)
		}
	}()
	m := &tcap.Unidirectional{
		Dialogue:   &tcap.Dialogue{Response: &tcap.AARE{ApplicationContextName: "1.2"}},
		Components: []tcap.Component{{Invoke: &tcap.Invoke{OpCode: tcap.LocalCode(1)}}},
	}
	out, err := m.Marshal()
	var field *tcap.FieldError
	if out != nil || !errors.Is(err, tcap.ErrUnexpectedDialoguePDU) || !errors.As(err, &field) || field.Path != "Dialogue" {
		t.Fatalf("Marshal = %x, %v; want dialogue FieldError", out, err)
	}
}

func TestReview4Table3UnderTolerance(t *testing.T) {
	for _, input := range []string{
		"62194801016b142812060700118605010201a0076005a10306012a",
		tlv("61", dialoguePortion(hexDialogueAS, "6005a10306012a"), "6c08a106020101020101"),
	} {
		var reports ber.ViolationLog
		m, err := tcap.Parse(hx(input), tcap.WithTolerance(&reports))
		var pe *tcap.ParseError
		if m != nil || !errors.As(err, &pe) || pe.Portion != tcap.PortionDialogue || !errors.Is(err, tcap.ErrUnexpectedDialoguePDU) {
			t.Fatalf("Parse %s = %#v, %v", input, m, err)
		}
		if len(reports.Snapshot()) != 0 {
			t.Fatal("failed Parse published reports")
		}
	}
}

func TestReview4DialogueFailureDiscardsComponents(t *testing.T) {
	// Q.774 (06/97) clause 3.2.2.1 discards components after an incorrect dialogue.
	// Strict decoding reports the dialogue violation before the component error.
	// Err describes that dialogue portion alone.
	input := hx("62204801016b142812060700118605010201a0076005a10306012a6c05a103020105")
	var w wire.TCMessage
	var codecFailure *wire.DecodeError
	var violation *ber.ValidationError
	codecErr := w.UnmarshalBER(input)
	if !errors.As(codecErr, &codecFailure) || !errors.As(codecErr, &violation) || codecFailure.Path != "begin.dialoguePortion" {
		t.Fatalf("codec dialogue precedence: %v", codecErr)
	}
	m, err := tcap.Parse(input)
	var pe *tcap.ParseError
	var decoded *wire.DecodeError
	if m != nil || !errors.As(err, &pe) || errors.As(err, &decoded) || pe.Portion != tcap.PortionDialogue || !errors.Is(err, tcap.ErrUnexpectedDialoguePDU) || pe.ComponentIndex != -1 || pe.Components != nil || pe.InvokeID != nil {
		t.Fatalf("dialogue failure: %#v, %v", m, err)
	}
}

func TestReview4TransactionIDTags(t *testing.T) {
	for _, tc := range []struct{ name, input, otid, dtid string }{
		{"Begin DTID at OTID position", "62054901026c00", "", ""},
		{"End OTID at DTID position", "64054801026c00", "", ""},
		{"Abort OTID at DTID position", "67054801024a00", "", ""},
		{"Continue swapped IDs", "65084901024801016c00", "", ""},
		{"Continue repeated OTID at DTID position", "65084801014801026c00", "", ""},
	} {
		for _, tolerant := range []bool{false, true} {
			for _, maxElements := range []int{0, 2, 3} {
				opts := []tcap.ParseOption{tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: maxElements})}
				if tolerant {
					opts = append(opts, tcap.WithTolerance(&ber.ViolationLog{}))
				}
				wantOTID := tc.otid
				// A codec decode-limit failure keeps Prefix without a repeat scan.
				if maxElements != 0 && tc.name == "Continue repeated OTID at DTID position" {
					wantOTID = "01"
				}
				_, err := tcap.Parse(hx(tc.input), opts...)
				var pe *tcap.ParseError
				if !errors.As(err, &pe) {
					t.Fatalf("expected ParseError: %v", err)
				}
				if pe.OTID.String() != wantOTID || pe.DTID.String() != tc.dtid {
					t.Errorf("%s tolerance %t MaxElements %d: %v; IDs %s/%s", tc.name, tolerant, maxElements, err, pe.OTID, pe.DTID)
				}
			}
		}
	}
}

// A truncated message keeps the IDs accepted by the codec (ITU-T Q.774
// (06/97) clause 3.3.4 and Table 7), without another scan for IDs.
func TestReview4TruncatedMessageKeepsPrefixIDs(t *testing.T) {
	for _, tc := range []struct{ name, input, otid, dtid string }{
		{"Begin cut after its OTID", "62064801016c", "01", ""},
		{"End cut after its DTID", "64064901026c", "", "02"},
	} {
		for _, tolerant := range []bool{false, true} {
			opts := []tcap.ParseOption{tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 2})}
			if tolerant {
				opts = append(opts, tcap.WithTolerance(&ber.ViolationLog{}))
			}
			_, err := tcap.Parse(hx(tc.input), opts...)
			var pe *tcap.ParseError
			if !errors.As(err, &pe) || pe.Portion != tcap.PortionTransaction || pe.OTID.String() != tc.otid || pe.DTID.String() != tc.dtid || errors.Is(err, ber.ErrResourceLimit) || !errors.Is(err, ber.ErrTruncated) {
				t.Fatalf("%s, tolerant %t: %v", tc.name, tolerant, err)
			}
		}
	}
}

// Data that ends inside an indefinite-length message is a failure of the
// transaction portion, not of the component it cuts (Q.774 clause 3.3.4).
func TestReview4TruncatedIndefiniteMessage(t *testing.T) {
	for _, tolerant := range []bool{false, true} {
		var opts []tcap.ParseOption
		if tolerant {
			opts = append(opts, tcap.WithTolerance(&ber.ViolationLog{}))
		}
		_, err := tcap.Parse(hx("62804801016c80a18002010102012d"), opts...)
		var pe *tcap.ParseError
		if !errors.As(err, &pe) || pe.Portion != tcap.PortionTransaction || pe.ComponentIndex != -1 || pe.InvokeID != nil || pe.OTID.String() != "01" || !errors.Is(err, ber.ErrTruncated) {
			t.Fatalf("tolerant %t: %#v, %v", tolerant, pe, err)
		}
	}
}

// A malformed element after a component portion that cannot be delimited
// breaks the transaction layout, so it is not reported as the failure of an
// earlier component (Q.773 (06/97) clause 3.1, Q.774 (06/97) clause 3.3.4).
func TestReview4MalformedTransactionTail(t *testing.T) {
	for _, input := range []string{
		"62114801016c80a103020105058000000000ff",
		"620e4801016c80a100058000000000ff",
	} {
		for _, tolerant := range []bool{false, true} {
			var opts []tcap.ParseOption
			if tolerant {
				opts = append(opts, tcap.WithTolerance(&ber.ViolationLog{}))
			}
			_, err := tcap.Parse(hx(input), opts...)
			var pe *tcap.ParseError
			if !errors.As(err, &pe) || pe.Portion != tcap.PortionTransaction || pe.ComponentIndex != -1 || pe.InvokeID != nil || pe.OTID.String() != "01" {
				t.Fatalf("%s, tolerant %t: %#v, %v", input, tolerant, pe, err)
			}
		}
	}
}

// A dialogue portion that the codec refuses keeps the OTID before it, which
// the ABRT of Q.774 (06/97) clause 3.2.2.1 is sent to.
func TestReview4DialogueFailureKeepsOTID(t *testing.T) {
	for _, input := range []string{
		"620c4801016b0728050201008100", // EXTERNAL identified by indirect-reference only
		"62094801016b0428028100",       // EXTERNAL without a reference
	} {
		var w wire.TCMessage
		codecErr := w.UnmarshalBER(hx(input))
		var failure *wire.DecodeError
		var location *ber.ElementError
		if !errors.As(codecErr, &failure) || !errors.As(codecErr, &location) || location.Offset() != 5 || len(location.ChildIndexes()) != 1 || location.ChildIndexes()[0] != 1 || failure.Prefix.Otid == nil || tcap.TransactionID(*failure.Prefix.Otid).String() != "01" {
			t.Fatalf("codec dialogue location and prefix: %v", codecErr)
		}
		_, err := tcap.Parse(hx(input))
		var pe *tcap.ParseError
		if !errors.As(err, &pe) || pe.Portion != tcap.PortionDialogue || pe.OTID.String() != "01" {
			t.Fatalf("%s: %#v, %v", input, pe, err)
		}
	}
}

// A dialogue portion whose header breaks Q.773 (06/97) clause 4.1.1 and whose
// length runs past the message breaks the transaction layout: the failure is
// the transaction portion's, though the codec locates it at the dialogue.
func TestReview4OverrunningDialoguePortion(t *testing.T) {
	_, err := tcap.Parse(hx("620e4801016b81280706012a82020780"))
	var pe *tcap.ParseError
	if !errors.As(err, &pe) || pe.Portion != tcap.PortionTransaction || pe.OTID.String() != "01" {
		t.Fatalf("%#v, %v", pe, err)
	}
}
