package tcap_test

import (
	"errors"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// Q.773 (06/97) Table 12 and Q.774 (06/97) clause 3.3.4 distinguish
// encoding failures from valid encodings with an invalid transaction layout.
func TestParsePAbortCause(t *testing.T) {
	const (
		bad       = tcap.PAbortCauseBadlyFormattedTransactionPortion
		incorrect = tcap.PAbortCauseIncorrectTransactionPortion
		unknown   = tcap.PAbortCauseUnrecognizedMessageType
		resource  = tcap.PAbortCauseResourceLimitation
	)
	type parseAbortCase struct {
		name, input string
		cause       int64
		portion     tcap.Portion
		tolerant    bool
		limits      tcap.DecodeLimits
		success     bool
	}
	cases := []parseAbortCase{
		{name: "truncated Begin", input: "620648027f016c", cause: bad},
		{name: "truncated Begin tolerant", input: "620648027f016c", tolerant: true, cause: bad},
		{name: "unexpected NULL in Begin", input: "620648027f010500", cause: incorrect},
		{name: "unexpected NULL in Begin tolerant", input: "620648027f010500", tolerant: true, cause: incorrect},
		{name: "empty data", cause: bad},
		{name: "tag only", input: "62", cause: bad},
		{name: "invalid high tag", input: "7f8000", cause: bad},
		{name: "invalid length", input: "62ff", cause: bad},
		{name: "primitive Begin", input: "4203480101", cause: unknown},
		{name: "primitive Unidirectional", input: "4100", cause: unknown},
		{name: "primitive End", input: "4403490101", cause: unknown},
		{name: "primitive Continue", input: "4506480101490102", cause: unknown},
		{name: "primitive Abort", input: "4703490101", cause: unknown},
		{name: "unknown message", input: "6300", cause: unknown},
		{name: "unknown before syntax", input: "63", cause: unknown},
		{name: "unknown before limit", input: "6303480101", limits: tcap.DecodeLimits{MaxWork: 1}, cause: unknown},
		{name: "octet after message", input: "620348010100", cause: bad},
		{name: "two messages", input: "62034801016203480101", cause: bad},
		{name: "truncated TID", input: "620448027f", cause: bad},
		{name: "truncated component", input: "620b4801016c06a104020101", cause: bad},
		{name: "indefinite Begin", input: "62804801010000", success: true},
		{name: "missing EOC", input: "6280480101", cause: bad},
		{name: "short long form strict", input: "628103480101", cause: bad},
		{name: "short long form tolerant", input: "628103480101", tolerant: true, success: true},
		{name: "nonminimal long form strict", input: "62820003480101", cause: bad},
		{name: "nonminimal long form tolerant", input: "62820003480101", tolerant: true, success: true},
		{name: "constructed TID strict", input: "62056803040101", cause: bad},
		{name: "constructed TID tolerant", input: "62056803040101", tolerant: true, success: true},
		{name: "five octet OTID", input: "620748050102030405", cause: incorrect},
		{name: "empty OTID", input: "62024800", cause: incorrect},
		{name: "Begin missing OTID", input: "6200", cause: incorrect},
		{name: "Begin with DTID", input: "6203490101", cause: incorrect},
		// A missing or wrong EXTERNAL in the dialogue portion is an element out
		// of place, not an encoding error (X.690 clause 8.14.3); the NULL after
		// it keeps the failure in the transaction portion.
		{name: "empty dialogue portion and unexpected NULL", input: "62074801016b000500", cause: incorrect},
		{name: "NULL dialogue portion and unexpected NULL", input: "62094801016b0205000500", cause: incorrect},
		{name: "Begin repeated OTID", input: "6206480101480102", cause: incorrect},
		{name: "Continue wrong tag", input: "650648027f010500", cause: incorrect},
		{name: "Continue reversed IDs", input: "6506490102480101", cause: incorrect},
		{name: "End missing DTID", input: "6400", cause: incorrect},
		{name: "Unidirectional missing components", input: "6100", cause: incorrect},
		{name: "Abort missing DTID", input: "6700", cause: incorrect},
		{name: "empty P-Abort INTEGER", input: "67054901014a00", cause: bad},
		// The P-Abort cause is in its place after a DTID that violates SIZE
		// (1..4), so its empty contents count (X.690 clause 8.3.1).
		{name: "empty DTID and empty P-Abort INTEGER", input: "670449004a00", cause: bad},
		// After an element that Abort does not admit, the P-Abort cause is out
		// of its place: its IMPLICIT tag does not give its type, so its contents
		// are not checked (X.690 clause 8.14.4).
		{name: "unexpected element and empty P-Abort INTEGER", input: "67074901014f004a00", cause: incorrect},
		{name: "P-Abort cause 200", input: "67074901014a0200c8", cause: incorrect},
		{name: "constructed P-Abort INTEGER", input: "67074901016a020500", cause: bad},
		{name: "malformed after wrong tag", input: "62074901016c020201", cause: bad},
		{name: "malformed component after wrong tag", input: "62084901016c03a10100", cause: bad},
		{name: "valid encoding wrong layout", input: "620a4901016c05a103020101", cause: incorrect},
		{name: "invalid EXTERNAL form and repeated OTID", input: "620f4801016b07280506012a8000480102", cause: bad},
		{name: "component failure", input: "620a4801016c05a103020101", portion: tcap.PortionComponent},
		// With a sound transaction portion, a missing EXTERNAL (X.690 clause
		// 8.14.3) or an encoding outside [0] to [2] (clause 8.18.1) fails the
		// dialogue portion.
		{name: "empty dialogue portion", input: "62054801016b00", portion: tcap.PortionDialogue},
		{name: "EXTERNAL encoding [3]", input: "620c4801016b07280506012a8300", portion: tcap.PortionDialogue},
		{name: "dialogue failure", input: tlv("62", hexOTID, dialoguePortion(hexDialogueAS, hexAAREAcc)), portion: tcap.PortionDialogue},
		// Q.773 clause 4.2.2.2 is not an encoding rule: an invoke ID of 200,
		// then a NULL that Begin does not admit.
		{name: "invoke ID out of range and unexpected NULL", input: "62104801016c09a107020200c802012d0500", cause: incorrect},
		{name: "invoke ID out of range and unexpected NULL tolerant", input: "62104801016c09a107020200c802012d0500", tolerant: true, cause: incorrect},
		// Behind an invoke ID out of range and an unexpected NULL, the NULL
		// of linkedId absent [1] has a contents octet (ITU-T X.690 (02/2021)
		// clauses 8.8.2 and 8.14.4).
		{name: "linked ID absent with contents", input: "62134801016c0ca10a020200c881010002012d0500", cause: bad},
		{name: "linked ID absent with contents tolerant", input: "62134801016c0ca10a020200c881010002012d0500", tolerant: true, cause: bad},
		// After the DTID, a REAL that Abort does not admit, with base bits
		// 11, which ITU-T X.690 (02/2021) clause 8.5.7.2 reserves. Its
		// universal tag gives its type wherever it stands.
		{name: "reserved REAL base after DTID", input: "67084901010903b00001", cause: bad},
		{name: "reserved REAL base after DTID tolerant", input: "67084901010903b00001", tolerant: true, cause: bad},
		// An empty OTID violates SIZE (1..4) but keeps the dialogue portion
		// in its place, where application-context-name [1], an EXPLICIT
		// tag, must be constructed (ITU-T X.690 (02/2021) clause 8.14.3).
		{name: "primitive application context after empty OTID", input: "621648006b122810060700118605010101a005600381012a", cause: bad},
		{name: "primitive application context after empty OTID tolerant", input: "621648006b122810060700118605010101a005600381012a", tolerant: true, portion: tcap.PortionDialogue},
		// An EXTERNAL's single-ASN1-type [0] must be constructed in a
		// parameter too (ITU-T X.690 (02/2021) clauses 8.14.3 and 8.18.1).
		{name: "primitive EXTERNAL encoding in parameter and unexpected NULL", input: "62164801016c0fa10d020200c802012d2804800205000500", cause: bad},
		{name: "primitive EXTERNAL encoding in parameter and unexpected NULL tolerant", input: "62164801016c0fa10d020200c802012d2804800205000500", tolerant: true, cause: bad},
		// A repeated transaction ID is out of its place (Q.773 (06/97)
		// clause 3.1), so its IMPLICIT tag gives no type to check (ITU-T
		// X.690 (02/2021) clause 8.14.4). The codec reads into it, and
		// tight limits stop it there.
		{name: "constructed repeated OTID", input: "620e4801016803040102300430020500", cause: incorrect},
		{name: "constructed repeated DTID", input: "65114801014901026903040103300430020500", cause: incorrect},
		{name: "constructed repeated OTID codec depth limit", input: "620e4801016803040102300430020500", limits: tcap.DecodeLimits{MaxDepth: 2}, cause: resource},
		{name: "constructed repeated DTID codec element limit", input: "65114801014901026903040103300430020500", limits: tcap.DecodeLimits{MaxElements: 4}, cause: resource},
		// After a NULL that the message does not admit, the component
		// portion is out of its place. Its arguments, results and parameters
		// are still the TC-user's syntax (ITU-T X.690 (02/2021) clause
		// 8.15), which Q.773 clause 4.1.1 does not cover, so a long-form
		// length below 128 or a constructed OCTET STRING there is not an
		// encoding fault. Its own fields remain TCAP syntax.
		{name: "misplaced Invoke argument with long-form length", input: "621548010105006c0ea10c020100020100048103616263", cause: incorrect},
		{name: "misplaced Invoke argument with long-form length tolerant", input: "621548010105006c0ea10c020100020100048103616263", tolerant: true, cause: incorrect},
		{name: "misplaced ReturnResultLast result with long-form length", input: "621748010105006c10a20e0201003009020100048103616263", cause: incorrect},
		{name: "misplaced ReturnResultNotLast result with long-form length", input: "621748010105006c10a70e0201003009020100048103616263", cause: incorrect},
		{name: "misplaced ReturnError parameter with long-form length", input: "621548010105006c0ea30c020100020101048103616263", cause: incorrect},
		{name: "misplaced Invoke argument with constructed OCTET STRING in End", input: "641649010205006c0fa10d02010102010124050403616263", cause: incorrect},
		{name: "misplaced Invoke argument with constructed OCTET STRING in Unidirectional", input: "611105006c0da10b0201010201012403040161", cause: incorrect},
		{name: "misplaced invoke ID with long-form length", input: "621548010105006c0ea10c028101000201000403616263", cause: bad},
		// An empty [0] in an EXTERNAL is a missing element (ITU-T X.690
		// (02/2021) clause 8.14.3), not an encoding fault, and the
		// whole-message check stops there as well, so an encoding fault
		// after it does not count: a truncated INTEGER after an argument's
		// EXTERNAL, and an INTEGER without contents octets after the
		// dialogue portion's.
		{name: "empty EXTERNAL [0] in argument then truncated INTEGER", input: "62164801016c0fa10d020101020101280506012aa0000201", cause: incorrect},
		{name: "empty EXTERNAL [0] in argument then truncated INTEGER tolerant", input: "62164801016c0fa10d020101020101280506012aa0000201", tolerant: true, cause: incorrect},
		{name: "empty dialogue EXTERNAL [0] then INTEGER without contents", input: "62144801016b0d280b060700118605010101a0000200", cause: incorrect},
		{name: "codec limit", input: "6203480101", limits: tcap.DecodeLimits{MaxWork: 1}, cause: resource},
		// A limit met only while inspecting keeps the codec's failure: a
		// repeated DTID with a long-form length below 128 (Q.773 clause
		// 4.1.1), and a truncated NULL.
		{name: "inspection limit after 4.1.1 failure", input: "6512480101490102698103040103300430020500", limits: tcap.DecodeLimits{MaxElements: 4}, cause: bad},
		{name: "inspection limit after truncation", input: "620448010105", limits: tcap.DecodeLimits{MaxElements: 2}, cause: bad},
	}
	// Each recognized message type can be malformed, have an incorrect layout,
	// or exceed a receiver's decode budget. No cause depends on transaction state.
	for _, mt := range []struct{ name, tag, children string }{
		{"Begin", "62", "480101"},
		{"Continue", "65", "480101490102"},
		{"End", "64", "490102"},
		{"Abort", "67", "490102"},
		{"Unidirectional", "61", "6c08a106020101020101"},
	} {
		valid := tlv(mt.tag, mt.children)
		cases = append(cases,
			parseAbortCase{name: mt.name + " trailing data", input: valid + "00", cause: bad},
			parseAbortCase{name: mt.name + " unexpected element", input: tlv(mt.tag, mt.children, "0500"), cause: incorrect},
			parseAbortCase{name: mt.name + " decode limit", input: valid, cause: resource, limits: tcap.DecodeLimits{MaxWork: 1}},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var opts []tcap.ParseOption
			var log tcap.ViolationLog
			if tc.tolerant {
				opts = append(opts, tcap.WithTolerance(&log))
			}
			if tc.limits != (tcap.DecodeLimits{}) {
				opts = append(opts, tcap.WithDecodeLimits(tc.limits))
			}
			msg, err := tcap.Parse(hx(tc.input), opts...)
			if tc.success {
				if err != nil || msg == nil {
					t.Fatalf("Parse = %v, %v", msg, err)
				}
				return
			}
			var pe *tcap.ParseError
			if msg != nil || !errors.As(err, &pe) {
				t.Fatalf("Parse = %v, %v", msg, err)
			}
			portion := tc.portion
			if portion == "" {
				portion = tcap.PortionTransaction
			}
			if pe.Portion != portion {
				t.Fatalf("Portion = %s, want %s: %v", pe.Portion, portion, err)
			}
			cause, ok := pe.PAbortCause()
			if ok != (portion == tcap.PortionTransaction) {
				t.Fatalf("PAbortCause ok = %t: %v", ok, err)
			}
			if ok {
				if value, fits := cause.AsInt64(); !fits || value != tc.cause {
					t.Fatalf("PAbortCause = %v, want %d: %v", cause, tc.cause, err)
				}
			}
			if len(log.Snapshot()) != 0 {
				t.Fatal("failure published violations")
			}
		})
	}
}

func TestParsePAbortCauseOwnership(t *testing.T) {
	_, err := tcap.Parse(hx("620648027f010500"))
	pe := asParseError(t, err)
	cause, ok := pe.PAbortCause()
	if !ok {
		t.Fatal("missing cause")
	}
	if err := cause.UnmarshalText([]byte("4")); err != nil {
		t.Fatal(err)
	}
	again, ok := pe.PAbortCause()
	if value, fits := again.AsInt64(); !ok || !fits || value != tcap.PAbortCauseIncorrectTransactionPortion {
		t.Fatalf("cause aliases result: %v, %t", again, ok)
	}
	pe.Err = tcap.ErrEmptyData
	stored, ok := pe.PAbortCause()
	if value, fits := stored.AsInt64(); !ok || !fits || value != tcap.PAbortCauseIncorrectTransactionPortion {
		t.Fatalf("cause was recomputed from Err: %v, %t", stored, ok)
	}
	pe.Portion = tcap.PortionDialogue
	if _, ok := pe.PAbortCause(); ok {
		t.Fatal("cause for changed Portion")
	}
	for _, pe := range []*tcap.ParseError{nil, {}, {Portion: tcap.PortionTransaction, Err: tcap.ErrEmptyData}} {
		if _, ok := pe.PAbortCause(); ok {
			t.Fatal("cause for error not produced by Parse")
		}
	}
}

// TestParsePAbortCauseInspectionLimit: a limit met only while inspecting a
// failed message is reported in Err, and the cause stays the codec's.
func TestParsePAbortCauseInspectionLimit(t *testing.T) {
	data := hx("6512480101490102698103040103300430020500")
	limits := tcap.DecodeLimits{MaxElements: 4}
	var w wire.TCMessage
	err := w.UnmarshalBER(data, ber.WithDecodeLimits(limits))
	if err == nil || errors.Is(err, ber.ErrResourceLimit) {
		t.Fatalf("codec must fail before the limit: %v", err)
	}
	_, err = tcap.Parse(data, tcap.WithDecodeLimits(limits))
	pe := asParseError(t, err)
	cause, ok := pe.PAbortCause()
	if value, fits := cause.AsInt64(); !errors.Is(err, ber.ErrResourceLimit) || !ok || !fits || value != tcap.PAbortCauseBadlyFormattedTransactionPortion {
		t.Fatalf("inspection limit = %v, %t: %v", cause, ok, err)
	}
}

func FuzzParsePAbortCause(f *testing.F) {
	for _, input := range []string{"", "62", "6300", "4203480101", "620648027f016c", "620648027f010500", "628103480101", "67054901014a00"} {
		f.Add(hx(input))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, opts := range [][]tcap.ParseOption{
			nil,
			{tcap.WithTolerance(&tcap.ViolationLog{})},
			{tcap.WithDecodeLimits(tcap.DecodeLimits{MaxDepth: 4, MaxElements: 8, MaxWork: 64})},
		} {
			_, err := tcap.Parse(data, opts...)
			if err == nil {
				continue
			}
			pe := asParseError(t, err)
			cause, ok := pe.PAbortCause()
			if ok != (pe.Portion == tcap.PortionTransaction) {
				t.Fatalf("PAbortCause ok = %t, Portion = %s: %v", ok, pe.Portion, err)
			}
			if !ok {
				continue
			}
			value, fits := cause.AsInt64()
			if !fits || value != tcap.PAbortCauseUnrecognizedMessageType && value != tcap.PAbortCauseBadlyFormattedTransactionPortion && value != tcap.PAbortCauseIncorrectTransactionPortion && value != tcap.PAbortCauseResourceLimitation {
				t.Fatalf("PAbortCause = %v: %v", cause, err)
			}
		}
	})
}
