package tcap_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"

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

// With WithTolerance, Parse accepts an empty transaction ID, and a
// failure derives it as well; without it, an empty ID is not derivable.
func TestReview3ToleratedEmptyIDs(t *testing.T) {
	var accepted, log ber.ViolationLog
	m, err := tcap.Parse(hx(tlv("62", "4800")), tcap.WithTolerance(&accepted))
	if begin, ok := m.(*tcap.Begin); err != nil || !ok || begin.OTID == nil || len(accepted.Snapshot()) != 1 {
		t.Fatalf("Parse = %#v, %v, %d violations", m, err, len(accepted.Snapshot()))
	}
	tolerant := tcap.WithTolerance(&log)
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
// rejects large inputs before allocating replay storage for their contents.
func TestReview3InspectionWithinWorkLimit(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		limits      *ber.DecodeLimits
		otid        string
	}{
		{"MaxWork 8", "6280" + "480101" + strings.Repeat("30020500", 100000) + "0000", &ber.DecodeLimits{MaxWork: 8}, "01"},
		{"default limits", "6280" + hexOTID + strings.Repeat("0500", 800000) + "0000", nil, "01020304"},
		{"indefinite children", "6280" + hexOTID + strings.Repeat("30800000", 100000) + "0000", nil, "01020304"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := hx(tc.input)
			var opts []tcap.ParseOption
			if tc.limits != nil {
				opts = append(opts, tcap.WithDecodeLimits(*tc.limits))
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := tcap.Parse(input, opts...)
			runtime.ReadMemStats(&after)
			var pe *tcap.ParseError
			if !errors.As(err, &pe) || !errors.Is(err, ber.ErrResourceLimit) || pe.OTID.String() != tc.otid {
				t.Fatalf("Parse = %v", err)
			}
			allocated := after.TotalAlloc - before.TotalAlloc
			t.Logf("Parse allocated %d octets", allocated)
			if allocated > 1<<20 {
				t.Fatalf("Parse allocated %d octets for rejected input", allocated)
			}
		})
	}
}

// MaxElements bounds decoding and inspection. The codec does not accept IDs
// after a non-ID child, even when the limits permit reading that child.
func TestReview3InspectionCountsAllElements(t *testing.T) {
	child := "3080" + "0500" + "0500" + "0500" + "0000"
	pe := reviewFailure(t, "6380"+child+child+hexDTID+"0000", tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 4}))
	if pe.DTID != nil || !errors.Is(pe, ber.ErrResourceLimit) {
		t.Fatalf("DTID %s after the element limit, %v", pe.DTID, pe.Err)
	}
	if pe := reviewFailure(t, "6380"+child+child+hexDTID+"0000"+"00"); pe.DTID != nil {
		t.Fatalf("nonleading DTID in codec Prefix: %s", pe.DTID)
	}
}

// The caller's MaxDepth bounds inspection as it bounds the codec. IDs after
// a non-ID child remain absent from Prefix with or without a depth failure.
func TestReview3InspectionWithinDepthLimit(t *testing.T) {
	deep := "3080" + "3080" + "3080" + "0000" + "0000" + "0000"
	pe := reviewFailure(t, "6380"+deep+"480101"+"0000", tcap.WithDecodeLimits(ber.DecodeLimits{MaxDepth: 2}))
	if pe.OTID != nil || !errors.Is(pe, ber.ErrResourceLimit) {
		t.Fatalf("OTID %s after a child deeper than MaxDepth, %v", pe.OTID, pe.Err)
	}
	if pe := reviewFailure(t, "6380"+deep+"480101"+"0000"+"00"); pe.OTID != nil {
		t.Fatalf("nonleading OTID in codec Prefix: %s", pe.OTID)
	}
}

// A decode limit inside the typed dialogue is a transaction portion failure,
// with the leading transaction ID preserved (Q.774 (06/97) Table 7).
func TestReview3ResourceLimitInPortion(t *testing.T) {
	// Tolerance permits the constructed BIT STRING so the work limit can be exercised
	// inside the typed dialogue (X.690 (02/2021) clause 8.6.4).
	pv := "03020780"
	for range 20 {
		pv = tlv("23", pv)
	}
	aarq := tlv("60", tlv("a0", pv), hexACN3)
	pe := reviewFailure(t, tlv("62", hexOTID, dialoguePortion(hexDialogueAS, aarq), tlv("6c", hexCodecBadInvoke)), tcap.WithDecodeLimits(ber.DecodeLimits{MaxWork: 64}), tcap.WithTolerance(&ber.ViolationLog{}))
	if pe.Portion != tcap.PortionTransaction || !errors.Is(pe, ber.ErrResourceLimit) || pe.OTID.String() != "01020304" {
		t.Fatalf("%+v: %v", pe, pe.Err)
	}
}

// With WithTolerance, an invoke ID that Parse accepts outside
// -128..127 is also reported after a failure (Q.774 (06/97) Table 5).
func TestReview3ToleratedInvokeID(t *testing.T) {
	var log ber.ViolationLog
	input := tlv("62", hexOTID, tlv("6c", tlv("a1", "020200c8", "8100", "02012d")))
	if pe := reviewFailure(t, input, tcap.WithTolerance(&log)); pe.InvokeID == nil || *pe.InvokeID != 200 || !errors.Is(pe, tcap.ErrInvalidLinkedID) {
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
			wantID := "01"
			if tc.limits.MaxWork != 0 {
				wantID = ""
			}
			if pe.OTID.String() != wantID || !errors.Is(pe, ber.ErrResourceLimit) {
				t.Fatalf("OTID %s, %v", pe.OTID, pe.Err)
			}
		})
	}
}

// Inspection stops at the first failing component; it does not scan the
// later components deeply enough to exhaust the decode limits.
func TestReview3InspectionStopsAtFirstFailure(t *testing.T) {
	constructedNull := tlv("a1", "020101", "02012d", "2500")
	components := "6c80" + constructedNull + "a180" + strings.Repeat("0500", 20) + "0000" + "0000"
	for _, input := range []string{
		tlv("62", hexOTID, components),
		"6280" + hexOTID + components + "0000",
	} {
		pe := reviewFailure(t, input, tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 10}))
		if pe.Portion != tcap.PortionComponent || pe.ComponentIndex != 0 || errors.Is(pe, ber.ErrResourceLimit) || !errors.Is(pe, ber.ErrInvalidTag) || pe.OTID.String() != "01020304" {
			t.Fatalf("%s: %+v: %v", input[:4], pe, pe.Err)
		}
	}
}

// Beyond the decode limits, an ID is taken at its position only from the
// elements that go-asn1 validated before its first failure. Here the first
// element has a constructed end-of-contents tag (X.690 (02/2021) clause
// 8.1.5), so the DTID after it is not derivable.
func TestReview3PositionalIDsStopAtValidationFailure(t *testing.T) {
	pe := reviewFailure(t, "65082001014901020500", tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 3}))
	if !errors.Is(pe, ber.ErrResourceLimit) || !errors.Is(pe, ber.ErrInvalidTag) || pe.OTID != nil || pe.DTID != nil {
		t.Fatalf("%+v: %v", pe, pe.Err)
	}
}

// Beyond the decode limits, the elements of a transaction ID sent in
// segments (X.690 (02/2021) clause 8.7.3) count against the limits as the
// decoder counts them, wherever their length is definite.
func TestReview3SegmentedIDsWithinLimits(t *testing.T) {
	for _, tc := range []struct {
		name, input, otid, dtid string
		limits                  ber.DecodeLimits
	}{
		{"depth", "65086803040101490102", "", "", ber.DecodeLimits{MaxDepth: 1}},
		{"elements", "65086803040101490102", "01", "", ber.DecodeLimits{MaxElements: 3}},
		{"elements after two segments", "6517680804020102040203044904050607086c05a103020105", "01020304", "", ber.DecodeLimits{MaxElements: 4}},
		{"nested segments", "6519680a240824060404010203044904050607086c05a103020105", "", "", ber.DecodeLimits{MaxDepth: 3}},
		{"within the limits", "6519680a240824060404010203044904050607086c05a103020105", "01020304", "05060708", ber.DecodeLimits{MaxDepth: 4, MaxElements: 7}},
		{"work of the segments", "620768030401010500", "", "", ber.DecodeLimits{MaxWork: 5}},
		{"work of indefinite segments", "6209688004010100000500", "", "", ber.DecodeLimits{MaxWork: 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pe := reviewFailure(t, tc.input, tcap.WithDecodeLimits(tc.limits), tcap.WithTolerance(&ber.ViolationLog{}))
			if pe.OTID.String() != tc.otid || pe.DTID.String() != tc.dtid || (pe.OTID == nil) != (tc.otid == "") || (pe.DTID == nil) != (tc.dtid == "") {
				t.Fatalf("IDs %s/%s, want %s/%s: %v", pe.OTID, pe.DTID, tc.otid, tc.dtid, pe.Err)
			}
		})
	}
}

// A component that cannot be delimited still reports its invoke ID when its
// first element is a complete INTEGER (ITU-T Q.774 (06/97) Table 5).
func TestReview3InvokeIDOfUndelimitedComponent(t *testing.T) {
	for _, input := range []string{
		"620e4801016c09a18002010504ff0000",
		"620a4801016c05a180020105",
	} {
		pe := reviewFailure(t, input)
		if pe.ComponentIndex != 0 || pe.ComponentType != tcap.ComponentTypeInvoke || pe.InvokeID == nil || *pe.InvokeID != 5 {
			t.Fatalf("%s: %+v", input, pe)
		}
	}
}

// A primitive element in the component portion has contents, not elements,
// so it has no invoke ID (Q.773 (06/97) Table 19 components are constructed).
func TestReview3NoInvokeIDOfPrimitiveElement(t *testing.T) {
	for _, element := range []string{"8180020105", "8103020105", "8503020105"} {
		pe := reviewFailure(t, tlv("62", hexOTID, tlv("6c", hexInvoke, element)))
		if pe.ComponentIndex != 1 || pe.InvokeID != nil {
			t.Fatalf("%s: index %d, InvokeID %v", element, pe.ComponentIndex, pe.InvokeID)
		}
	}
}

// Parsing deeply segmented IDs has an absolute allocation bound
// (ITU-T X.690 (02/2021) clause 8.7.3).
func TestReview3SegmentedIDCost(t *testing.T) {
	id := tlv("04", strings.Repeat("aa", 1<<20))
	for range 120 {
		id = tlv("24", id)
	}
	input := hx(tlv("62", tlv("68", id), tlv("6c", hexCodecBadInvoke)))
	for _, tc := range []struct {
		name     string
		tolerant bool
		budget   int64
	}{
		{"strict", false, 4 << 20},
		{"tolerant", true, 48 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []tcap.ParseOption
			var log ber.ViolationLog
			if tc.tolerant {
				opts = append(opts, tcap.WithTolerance(&log))
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := tcap.Parse(input, opts...)
			runtime.ReadMemStats(&after)
			var pe *tcap.ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse = %v", err)
			}
			wantLength := 0
			if tc.tolerant {
				wantLength = 1 << 20
			}
			if len(pe.OTID) != wantLength {
				t.Fatalf("OTID has %d octets, want %d: %v", len(pe.OTID), wantLength, err)
			}
			if tc.tolerant && errors.Is(err, ber.ErrResourceLimit) {
				t.Fatalf("segmented bytes charged more than once: %v", err)
			}
			allocated := after.TotalAlloc - before.TotalAlloc
			t.Logf("Parse allocated %d octets", allocated)
			if allocated > uint64(tc.budget) {
				t.Fatalf("Parse allocated %d octets", allocated)
			}
		})
	}
}

// Segments count against MaxElements. An ID after a malformed preceding
// child is not accepted, even when the element limit would permit it
// (X.690 (02/2021) clause 8.8.1).
func TestReview3SegmentsCountAgainstMaxElements(t *testing.T) {
	otid := tlv("68", strings.Repeat("0400", 19), "040401020304")
	input := tlv("63", "2500", otid)
	if pe := reviewFailure(t, input, tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 10}), tcap.WithTolerance(&ber.ViolationLog{})); pe.OTID != nil {
		t.Fatalf("OTID %s from 21 elements under MaxElements 10", pe.OTID)
	}
	if pe := reviewFailure(t, input, tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 30}), tcap.WithTolerance(&ber.ViolationLog{})); pe.OTID != nil {
		t.Fatalf("nonleading OTID under MaxElements 30: %s", pe.OTID)
	}
}
