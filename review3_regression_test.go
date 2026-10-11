package tcap_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

const (
	// An Invoke whose parameter is a constructed NULL, which X.690 (02/2021)
	// clause 8.8.1 makes primitive. The codec reports it before the failures
	// of the elements that precede it.
	hexConstructedNullInvoke = "a108020106" + "02012d" + "2500"
	// A dialogue portion whose EXTERNAL has no encoding (X.690 (02/2021)
	// clause 8.18, Q.773 (06/97) Table 30).
	hexDialogueNoEncoding = "6b0b" + "2809" + hexDialogueAS
)

// Err is the failure of the dialogue portion or component that Portion and
// ComponentIndex designate, also when the codec reports a later element first;
// ITU-T Q.774 (06/97) clause 3.2.2.2 discards the components that follow.
func TestReview3ErrIsTheLocatedFailure(t *testing.T) {
	for _, tc := range []struct {
		name, alone, input string
		portion            tcap.Portion
	}{
		{
			"component",
			tlv("62", hexOTID, tlv("6c", hexCodecBadInvoke)),
			tlv("62", hexOTID, tlv("6c", hexCodecBadInvoke, hexConstructedNullInvoke)),
			tcap.PortionComponent,
		},
		{
			"dialogue portion",
			tlv("62", hexOTID, hexDialogueNoEncoding, tlv("6c", hexInvoke)),
			tlv("62", hexOTID, hexDialogueNoEncoding, tlv("6c", hexInvoke, hexConstructedNullInvoke)),
			tcap.PortionDialogue,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alone, pe := reviewFailure(t, tc.alone), reviewFailure(t, tc.input)
			if pe.Portion != tc.portion || alone.Portion != tc.portion || pe.ComponentIndex != alone.ComponentIndex {
				t.Fatalf("located %s %d, alone %s %d", pe.Portion, pe.ComponentIndex, alone.Portion, alone.ComponentIndex)
			}
			if pe.Error() != alone.Error() || errors.Is(pe, ber.ErrInvalidTag) {
				t.Fatalf("Err = %v, want %v", pe.Err, alone.Err)
			}
		})
	}
}

// With WithConstraintTolerance, Parse accepts an empty transaction ID, and a
// failure derives it as well; without it, an empty ID is not derivable.
func TestReview3ToleratedEmptyIDs(t *testing.T) {
	var accepted, log ber.ViolationLog
	m, err := tcap.Parse(hx(tlv("62", "4800")), tcap.WithConstraintTolerance(&accepted))
	if begin, ok := m.(*tcap.Begin); err != nil || !ok || begin.OTID == nil || len(accepted.Snapshot()) != 1 {
		t.Fatalf("Parse = %#v, %v, %d violations", m, err, len(accepted.Snapshot()))
	}
	tolerant := tcap.WithConstraintTolerance(&log)
	for _, input := range []string{
		tlv("62", "4800", tlv("6c", hexCodecBadInvoke)),
		tlv("62", "4800", tlv("6c", hexLinkedAbsent)),
	} {
		if pe := reviewFailure(t, input, tolerant); pe.OTID == nil || len(pe.OTID) != 0 {
			t.Fatalf("%s: tolerant OTID %#v", input, pe.OTID)
		}
		if pe := reviewFailure(t, input); pe.OTID != nil {
			t.Fatalf("%s: strict OTID %#v", input, pe.OTID)
		}
	}
	pe := reviewFailure(t, tlv("65", hexOTID, "4900", tlv("6c", hexLinkedAbsent)), tolerant)
	if pe.DTID == nil || len(pe.DTID) != 0 || pe.OTID.String() != "01020304" {
		t.Fatalf("Continue: OTID %#v, DTID %#v", pe.OTID, pe.DTID)
	}
	if len(log.Snapshot()) != 0 {
		t.Fatalf("failed parses published %d violations", len(log.Snapshot()))
	}
}

// When the message cannot be decoded, its indefinite contents still end at
// their end-of-contents indicator (Q.773 (06/97) clause 4.1.2.3): what
// follows is not a transaction ID of the message. A child nested 129 levels
// deep exceeds the default depth limit within the message, not on its own.
func TestReview3ScanEndsAtEndOfContents(t *testing.T) {
	deep := strings.Repeat("3080", 129) + strings.Repeat("0000", 129)
	pe := reviewFailure(t, "6380"+deep+"0000"+hexOTID)
	if pe.OTID != nil || pe.DTID != nil || !errors.Is(pe, ber.ErrResourceLimit) {
		t.Fatalf("IDs after the end of an unrecognized message: %s/%s, %v", pe.OTID, pe.DTID, pe.Err)
	}
	pe = reviewFailure(t, "6280"+hexOTID+deep+"0000"+"48040a0b0c0d")
	if pe.OTID.String() != "01020304" {
		t.Fatalf("an element after the end of a Begin hides its OTID: %+v", pe)
	}
	pe = reviewFailure(t, "6380"+"4f00"+"4e00"+"0000"+"480101", tcap.WithDecodeLimits(ber.DecodeLimits{MaxWork: 3}))
	if pe.OTID != nil || pe.DTID != nil {
		t.Fatalf("IDs after the end of an unrecognized message: %s/%s", pe.OTID, pe.DTID)
	}
}

// Inspection after a failure keeps within the caller's decode limits and
// costs about what the codec does: it does not decode every child of a large
// message again.
func TestReview3InspectionWithinWorkLimit(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		opts        []tcap.ParseOption
		otid        string
	}{
		{"MaxWork 8", "6280" + "480101" + strings.Repeat("30020500", 100000) + "0000", []tcap.ParseOption{tcap.WithDecodeLimits(ber.DecodeLimits{MaxWork: 8})}, "01"},
		{"default limits", "6280" + hexOTID + strings.Repeat("0500", 800000) + "0000", nil, "01020304"},
		{"indefinite children", "6280" + hexOTID + strings.Repeat("30800000", 100000) + "0000", nil, "01020304"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := hx(tc.input)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := tcap.Parse(input, tc.opts...)
			runtime.ReadMemStats(&after)
			var pe *tcap.ParseError
			if !errors.As(err, &pe) || !errors.Is(err, ber.ErrResourceLimit) || pe.OTID.String() != tc.otid {
				t.Fatalf("Parse = %v", err)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
				t.Fatalf("inspection allocated %d octets", allocated)
			}
		})
	}
}

// MaxElements counts every element that inspection reads in a message, as
// it counts every element the codec reads: an ID after the limit is not
// examined.
func TestReview3InspectionCountsAllElements(t *testing.T) {
	child := "3080" + "0500" + "0500" + "0500" + "0000"
	pe := reviewFailure(t, "6380"+child+child+hexDTID+"0000", tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 4}))
	if pe.DTID != nil || !errors.Is(pe, ber.ErrResourceLimit) {
		t.Fatalf("DTID %s after the element limit, %v", pe.DTID, pe.Err)
	}
	if pe := reviewFailure(t, "6380"+child+child+hexDTID+"0000"+"00"); pe.DTID.String() != "05060708" {
		t.Fatalf("within the default limits: DTID %s", pe.DTID)
	}
}

// The caller's MaxDepth bounds inspection as it bounds the codec: an element
// after a child nested deeper than the limit is not examined.
func TestReview3InspectionWithinDepthLimit(t *testing.T) {
	deep := "3080" + "3080" + "3080" + "0000" + "0000" + "0000"
	pe := reviewFailure(t, "6380"+deep+"480101"+"0000", tcap.WithDecodeLimits(ber.DecodeLimits{MaxDepth: 2}))
	if pe.OTID != nil || !errors.Is(pe, ber.ErrResourceLimit) {
		t.Fatalf("OTID %s after a child deeper than MaxDepth, %v", pe.OTID, pe.Err)
	}
	if pe := reviewFailure(t, "6380"+deep+"480101"+"0000"+"00"); pe.OTID.String() != "01" {
		t.Fatalf("within the default limits: OTID %s", pe.OTID)
	}
}

// A decode limit that inspection meets in a portion the codec decoded as an
// open type is the cause, as when the codec meets it (Portion transaction).
func TestReview3ResourceLimitInPortion(t *testing.T) {
	// protocol-version as a BIT STRING constructed 20 levels deep (X.690
	// (02/2021) clause 8.6.4), which the codec carries inside the EXTERNAL.
	pv := "03020780"
	for range 20 {
		pv = tlv("23", pv)
	}
	aarq := tlv("60", tlv("a0", pv), hexACN3)
	pe := reviewFailure(t, tlv("62", hexOTID, dialoguePortion(hexDialogueAS, aarq), tlv("6c", hexCodecBadInvoke)), tcap.WithDecodeLimits(ber.DecodeLimits{MaxWork: 200}))
	if pe.Portion != tcap.PortionTransaction || !errors.Is(pe, ber.ErrResourceLimit) || pe.OTID.String() != "01020304" {
		t.Fatalf("%+v: %v", pe, pe.Err)
	}
}

// With WithConstraintTolerance, an invoke ID that Parse accepts outside
// -128..127 is also reported after a failure (Q.774 (06/97) Table 5).
func TestReview3ToleratedInvokeID(t *testing.T) {
	var log ber.ViolationLog
	input := tlv("62", hexOTID, tlv("6c", tlv("a1", "020200c8", "8100", "02012d")))
	if pe := reviewFailure(t, input, tcap.WithConstraintTolerance(&log)); pe.InvokeID == nil || *pe.InvokeID != 200 || !errors.Is(pe, tcap.ErrInvalidLinkedID) {
		t.Fatalf("tolerant: %+v", pe)
	}
	if pe := reviewFailure(t, input); pe.InvokeID != nil {
		t.Fatalf("strict: InvokeID %d", *pe.InvokeID)
	}
}

// The elements inside a child are delimited as the decoder delimits them, so
// that a malformed element in a later component leaves an earlier failure
// located (ITU-T Q.774 (06/97) clause 3.2.2.2): a primitive with an
// indefinite length (X.690 (02/2021) clause 8.1.3.2) in the second Invoke.
func TestReview3LaterMalformedElement(t *testing.T) {
	later := "a180" + "020106" + "02012d" + "0580" + "0000" + "0000"
	for _, tc := range []struct {
		name, alone, input string
		portion            tcap.Portion
	}{
		{"component", tlv("62", hexOTID, tlv("6c", hexCodecBadInvoke)), tlv("62", hexOTID, "6c80"+hexCodecBadInvoke+later+"0000"), tcap.PortionComponent},
		{"dialogue portion", tlv("62", hexOTID, hexDialogueNoEncoding, tlv("6c", hexInvoke)), tlv("62", hexOTID, hexDialogueNoEncoding, "6c80"+hexInvoke+later+"0000"), tcap.PortionDialogue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alone, pe := reviewFailure(t, tc.alone), reviewFailure(t, tc.input)
			if pe.Portion != tc.portion || pe.ComponentIndex != alone.ComponentIndex || pe.Error() != alone.Error() {
				t.Fatalf("located %s %d: %v; alone %s %d: %v", pe.Portion, pe.ComponentIndex, pe.Err, alone.Portion, alone.ComponentIndex, alone.Err)
			}
		})
	}
}

// When the message exceeds the decode limits, the transaction ID is taken
// from where the message type carries it without looking for repetitions,
// whichever limit ends the decoding.
func TestReview3IDsAtTheirPositionsBeyondLimits(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		limits      ber.DecodeLimits
	}{
		{"MaxElements", "6280" + "480101" + "3080" + "0500" + "0000" + "480102" + "0000", ber.DecodeLimits{MaxElements: 3}},
		{"MaxDepth", "6280" + "480101" + "3080" + "3080" + "0000" + "0000" + "480102" + "0000", ber.DecodeLimits{MaxDepth: 2}},
		{"MaxWork", "6206" + "480101" + "480501", ber.DecodeLimits{MaxWork: 3}},
		{"repetition before the limit", "6280" + "480101" + "480102" + "3080" + "0500" + "0500" + "0000" + "0000", ber.DecodeLimits{MaxElements: 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pe := reviewFailure(t, tc.input, tcap.WithDecodeLimits(tc.limits))
			if pe.OTID.String() != "01" || !errors.Is(pe, ber.ErrResourceLimit) {
				t.Fatalf("OTID %s, %v", pe.OTID, pe.Err)
			}
		})
	}
}

// A decode limit that only inspection meets, after the decoder stopped at an
// earlier malformed element, is reported with the decoder's failure, so that
// Err tells that the transaction IDs come from their positions.
func TestReview3InspectionLimitIsReported(t *testing.T) {
	constructedNull := tlv("a1", "020101", "02012d", "2500")
	components := "6c80" + constructedNull + "a180" + strings.Repeat("0500", 20) + "0000" + "0000"
	for _, input := range []string{
		tlv("62", hexOTID, components),
		"6280" + hexOTID + components + "0000",
	} {
		pe := reviewFailure(t, input, tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 10}))
		if pe.Portion != tcap.PortionTransaction || !errors.Is(pe, ber.ErrResourceLimit) || !errors.Is(pe, ber.ErrInvalidTag) || pe.OTID.String() != "01020304" {
			t.Fatalf("%s: %+v: %v", input[:4], pe, pe.Err)
		}
	}
}
