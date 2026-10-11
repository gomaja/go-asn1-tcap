package tcap_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// Components that the codec rejects (an Invoke without an operation code)
// and that a receiver rule rejects after the codec accepted them.
const (
	hexCodecBadInvoke  = "a103020105"
	hexLinkedAbsent    = "a108020103" + "8100" + "02012d" // linkedId absent [1] NULL, Q.773 Table 20
	hexInvokeID200     = "a107020200c8" + "02012d"        // invokeId 200, outside Q.773 clause 4.2.2.2
	hexOTIDFiveOctets  = "48050102030405"
	hexDTIDFiveOctets  = "49050102030405"
	hexDeepIndefinites = 200
)

// Err describes the element that Portion and ComponentIndex designate, also
// when the codec fails later in the message (ITU-T Q.774 (06/97) Table 5 and
// clause 3.2.2.1 choose the response from it).
func TestReview2ErrMatchesLocation(t *testing.T) {
	t.Run("receiver rule before a codec failure", func(t *testing.T) {
		pe := reviewFailure(t, tlv("62", hexOTID, tlv("6c", hexLinkedAbsent, hexCodecBadInvoke)))
		if pe.Portion != tcap.PortionComponent || pe.ComponentIndex != 0 || pe.ComponentType != tcap.ComponentTypeInvoke || pe.InvokeID == nil || *pe.InvokeID != 3 {
			t.Fatalf("context = %+v", pe)
		}
		if !errors.Is(pe, tcap.ErrInvalidLinkedID) {
			t.Fatalf("Err = %v, want ErrInvalidLinkedID", pe.Err)
		}
	})
	t.Run("constraint before a codec failure", func(t *testing.T) {
		pe := reviewFailure(t, tlv("62", hexOTID, tlv("6c", hexInvokeID200, hexCodecBadInvoke)))
		var ce *ber.ConstraintError
		if pe.ComponentIndex != 0 || !errors.As(pe, &ce) {
			t.Fatalf("context = %+v, Err = %v", pe, pe.Err)
		}
	})
	t.Run("dialogue placement before a codec failure", func(t *testing.T) {
		for _, input := range []string{
			tlv("62", hexOTID, dialoguePortion(hexDialogueAS, hexAAREAcc), tlv("6c", hexCodecBadInvoke)),
			tlv("61", dialoguePortion(hexDialogueAS, hexAARQ), tlv("6c", hexCodecBadInvoke)),
		} {
			pe := reviewFailure(t, input)
			if pe.Portion != tcap.PortionDialogue || !errors.Is(pe, tcap.ErrUnexpectedDialoguePDU) {
				t.Fatalf("%s: context = %+v, Err = %v", input, pe, pe.Err)
			}
		}
	})
}

// With WithConstraintTolerance, the transaction IDs that Parse accepts are
// also the ones a failure reports.
func TestReview2ToleratedIDsDerivable(t *testing.T) {
	var log ber.ViolationLog
	pe := reviewFailure(t, tlv("62", hexOTIDFiveOctets, tlv("6c", hexCodecBadInvoke)), tcap.WithConstraintTolerance(&log))
	if pe.Portion != tcap.PortionComponent || pe.OTID.String() != "0102030405" {
		t.Fatalf("codec path: %+v, OTID %s", pe, pe.OTID)
	}
	pe = reviewFailure(t, tlv("65", hexOTID, hexDTIDFiveOctets, tlv("6c", hexLinkedAbsent)), tcap.WithConstraintTolerance(&log))
	if pe.Portion != tcap.PortionComponent || pe.DTID.String() != "0102030405" || pe.OTID.String() != "01020304" {
		t.Fatalf("receiver path: %+v, IDs %s/%s", pe, pe.OTID, pe.DTID)
	}
	if len(log.Snapshot()) != 0 {
		t.Fatalf("failed parses published %d violations", len(log.Snapshot()))
	}
}

// The leading transaction ID stays derivable when a later, deeply nested
// element exceeds the decode limits or the immediate scan reaches its limit
// (Q.774 Table 7).
func TestReview2IDsBeforeLimits(t *testing.T) {
	deep := "6280" + hexOTID + "6c80" + "a180" + "020101" + "02012d" + strings.Repeat("3080", hexDeepIndefinites) + "0500" + strings.Repeat("0000", hexDeepIndefinites) + "0000" + "0000" + "0000"
	pe := reviewFailure(t, deep)
	if pe.Portion != tcap.PortionTransaction || pe.OTID.String() != "01020304" {
		t.Fatalf("deep: %+v, OTID %s", pe, pe.OTID)
	}
	// The decoder counts the message as its first element.
	pe = reviewFailure(t, tlv("65", hexOTID, hexDTID, tlv("6c", hexInvoke)), tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 3}))
	if !errors.Is(pe, ber.ErrResourceLimit) || pe.OTID.String() != "01020304" || pe.DTID.String() != "05060708" {
		t.Fatalf("element limit: %+v, IDs %s/%s", pe, pe.OTID, pe.DTID)
	}
	pe = reviewFailure(t, tlv("65", hexOTID, hexDTID, tlv("6c", hexInvoke)), tcap.WithDecodeLimits(ber.DecodeLimits{MaxElements: 2}))
	if pe.OTID.String() != "01020304" || pe.DTID != nil {
		t.Fatalf("element limit before the DTID: IDs %s/%s", pe.OTID, pe.DTID)
	}
}

// A primitive element is not a message; its contents are not read as
// transaction IDs (Q.773 Table 8).
func TestReview2PrimitiveOuterElement(t *testing.T) {
	pe := reviewFailure(t, "4206"+hexOTID)
	if pe.MessageType != "" || pe.OTID != nil || pe.DTID != nil {
		t.Fatalf("%+v, OTID %s", pe, pe.OTID)
	}
}

// Components is nil when no component precedes the failing one, on the
// codec path and on the receiver path alike.
func TestReview2NoPrefixIsNil(t *testing.T) {
	for _, input := range []string{
		tlv("62", hexOTID, tlv("6c", hexInvokeID200)),
		tlv("62", hexOTID, tlv("6c", hexCodecBadInvoke)),
	} {
		pe := reviewFailure(t, input)
		if pe.ComponentIndex != 0 || pe.Components != nil {
			t.Fatalf("%s: index %d, Components %#v", input, pe.ComponentIndex, pe.Components)
		}
	}
}

// Error carries the package prefix once.
func TestReview2ErrorTextPrefix(t *testing.T) {
	pe := reviewFailure(t, tlv("62", hexOTID, dialoguePortion(hexDialogueAS, hexAAREAcc)))
	if got := pe.Error(); strings.Count(got, "tcap:") != 1 || strings.Contains(got, "\n") {
		t.Fatalf("Error() = %q", got)
	}
	_, err := (&tcap.Begin{OTID: tcap.TransactionID{1}, Components: []tcap.Component{{}}}).Marshal()
	if err == nil || strings.Count(err.Error(), "tcap:") != 1 {
		t.Fatalf("Marshal error = %v", err)
	}
}
