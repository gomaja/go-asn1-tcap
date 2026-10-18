package tcap_test

import (
	"errors"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func TestParseRejectsInvalidOptions(t *testing.T) {
	for _, opts := range [][]tcap.ParseOption{
		{tcap.WithTolerance(nil)},
		{tcap.WithTolerance(&ber.ViolationLog{}), tcap.WithTolerance(nil)},
		{tcap.WithDecodeLimits(ber.DecodeLimits{MaxWork: -1})},
	} {
		_, err := tcap.Parse([]byte{0}, opts...)
		var pe *tcap.ParseError
		if !errors.Is(err, tcap.ErrInvalidParseOption) || !errors.Is(err, ber.ErrInvalidValue) || errors.As(err, &pe) {
			t.Fatalf("options: %v", err)
		}
	}
	if err := ber.ValidateDecodeOptions(ber.WithTolerance(nil)); !errors.Is(err, ber.ErrInvalidValue) {
		t.Fatalf("runtime nil-log validation: %v", err)
	}
}

func TestParseLastToleranceWins(t *testing.T) {
	// Exercise the codec's component ID bounds with separate logs.
	for _, component := range []string{
		tlv("a1", "020200c8", "020101"),
		tlv("a1", "020101", "800200c8", "020101"),
		tlv("a2", "020200c8"),
		tlv("a7", "020200c8"),
		tlv("a3", "020200c8", "020101"),
		tlv("a4", "020200c8", "800100"),
	} {
		for _, firstNil := range []bool{false, true} {
			var first, second ber.ViolationLog
			firstLog := &first
			if firstNil {
				firstLog = nil
			}
			m, err := tcap.Parse(hx(tlv("62", "480101", tlv("6c", component))),
				tcap.WithTolerance(firstLog), tcap.WithTolerance(&second))
			if err != nil || m == nil || len(first.Snapshot()) != 0 || len(second.Snapshot()) != 1 {
				t.Fatalf("component %s, first nil %t: Parse = %#v, %v; logs %v / %v", component, firstNil, m, err, first.Snapshot(), second.Snapshot())
			}
		}
	}
}
