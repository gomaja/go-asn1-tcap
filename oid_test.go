package tcap_test

import (
	"errors"
	"math"
	"reflect"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// Rules of oid.go and contract 3.11: canonical dotted decimal, at least two
// arcs, first arc 0..2, second arc at most 39 under a first arc of 0 or 1
// (ITU-T X.690 (02/2021) clause 8.19.4), arcs within uint64, and the first
// subidentifier X*40+Y within uint64.

var validOIDs = []struct {
	s    string
	arcs []uint64
}{
	{"0.0", []uint64{0, 0}},
	{"0.39", []uint64{0, 39}},
	{"1.0", []uint64{1, 0}},
	{"1.39", []uint64{1, 39}},
	{"2.0", []uint64{2, 0}},
	{"2.39", []uint64{2, 39}},
	{"2.40", []uint64{2, 40}},
	{"2.999", []uint64{2, 999}},
	{"1.2.3.4", []uint64{1, 2, 3, 4}},
	{"0.4.0.0.1.0.20.3", []uint64{0, 4, 0, 0, 1, 0, 20, 3}},
	{"0.0.17.773.1.1.1", []uint64{0, 0, 17, 773, 1, 1, 1}},
	{"1.2.0", []uint64{1, 2, 0}},
	{"1.2.18446744073709551615", []uint64{1, 2, math.MaxUint64}},
	// 2*40 + 18446744073709551535 = 2^64 - 1.
	{"2.18446744073709551535", []uint64{2, math.MaxUint64 - 80}},
}

var invalidOIDs = []string{
	"", "0", "1", "2", ".", "..", "0.", ".0", "1..2", ".1.2", "1.2.",
	"3.0", "9.1", "0.40", "1.40", "0.100",
	"01.2", "1.02", "1.2.03", "00.1", "1.00",
	"+1.2", "-1.2", "1.-2", " 1.2", "1.2 ", "1. 2", "1 .2",
	"1.2a", "a.b", "1,2", "1_2", "0x1.2", "1.2.3\x00", "1.2\n", "١.٢",
	"1.2.3.", "1:2",
}

var unrepresentableOIDs = []string{
	"1.2.18446744073709551616",
	"1.2.99999999999999999999999",
	"0.4.0.18446744073709551616.1",
	// 2*40 + 18446744073709551536 = 2^64.
	"2.18446744073709551536",
	"2.18446744073709551615",
	"2.18446744073709551616",
}

func TestParseOID(t *testing.T) {
	for _, c := range validOIDs {
		got, err := tcap.ParseOID(c.s)
		if err != nil || got != tcap.OID(c.s) {
			t.Errorf("ParseOID(%q) = %q, %v", c.s, got, err)
		}
	}
	for _, s := range invalidOIDs {
		if got, err := tcap.ParseOID(s); !errors.Is(err, tcap.ErrInvalidOID) {
			t.Errorf("ParseOID(%q) = %q, %v; want ErrInvalidOID", s, got, err)
		}
	}
	for _, s := range unrepresentableOIDs {
		if got, err := tcap.ParseOID(s); !errors.Is(err, tcap.ErrUnrepresentableValue) {
			t.Errorf("ParseOID(%q) = %q, %v; want ErrUnrepresentableValue", s, got, err)
		}
	}
}

func TestOIDArcs(t *testing.T) {
	for _, c := range validOIDs {
		arcs, err := tcap.OID(c.s).Arcs()
		if err != nil || !reflect.DeepEqual(arcs, c.arcs) {
			t.Errorf("OID(%q).Arcs() = %v, %v; want %v", c.s, arcs, err, c.arcs)
		}
	}
	for _, s := range invalidOIDs {
		if _, err := tcap.OID(s).Arcs(); !errors.Is(err, tcap.ErrInvalidOID) {
			t.Errorf("OID(%q).Arcs() error = %v; want ErrInvalidOID", s, err)
		}
	}
	for _, s := range unrepresentableOIDs {
		if _, err := tcap.OID(s).Arcs(); !errors.Is(err, tcap.ErrUnrepresentableValue) {
			t.Errorf("OID(%q).Arcs() error = %v; want ErrUnrepresentableValue", s, err)
		}
	}
	// The result is the caller's.
	arcs, err := tcap.OID("1.2.3").Arcs()
	if err != nil {
		t.Fatal(err)
	}
	arcs[2] = 9
	if again, _ := tcap.OID("1.2.3").Arcs(); !reflect.DeepEqual(again, []uint64{1, 2, 3}) {
		t.Errorf("Arcs after changing an earlier result = %v", again)
	}
}

func TestOIDFromArcs(t *testing.T) {
	for _, c := range validOIDs {
		got, err := tcap.OIDFromArcs(c.arcs...)
		if err != nil || got != tcap.OID(c.s) {
			t.Errorf("OIDFromArcs(%v) = %q, %v; want %q", c.arcs, got, err, c.s)
		}
	}
	invalid := [][]uint64{nil, {}, {0}, {2}, {3, 0}, {0, 40}, {1, 40}}
	for _, arcs := range invalid {
		if got, err := tcap.OIDFromArcs(arcs...); !errors.Is(err, tcap.ErrInvalidOID) {
			t.Errorf("OIDFromArcs(%v) = %q, %v; want ErrInvalidOID", arcs, got, err)
		}
	}
	unrepresentable := [][]uint64{{2, math.MaxUint64 - 79}, {2, math.MaxUint64}, {2, math.MaxUint64, 1}}
	for _, arcs := range unrepresentable {
		if got, err := tcap.OIDFromArcs(arcs...); !errors.Is(err, tcap.ErrUnrepresentableValue) {
			t.Errorf("OIDFromArcs(%v) = %q, %v; want ErrUnrepresentableValue", arcs, got, err)
		}
	}
}

func TestOIDRoundTrip(t *testing.T) {
	for _, c := range validOIDs {
		oid, err := tcap.ParseOID(c.s)
		if err != nil {
			t.Fatalf("ParseOID(%q): %v", c.s, err)
		}
		arcs, err := oid.Arcs()
		if err != nil {
			t.Fatalf("Arcs(%q): %v", c.s, err)
		}
		back, err := tcap.OIDFromArcs(arcs...)
		if err != nil || back != oid {
			t.Errorf("round trip of %q: %q, %v", c.s, back, err)
		}
	}
}

// TestOIDComparable: OIDs compare with == and can be constants (oid.go).
func TestOIDComparable(t *testing.T) {
	const a tcap.OID = "0.4.0.0.1.0.20.3"
	b, err := tcap.OIDFromArcs(0, 4, 0, 0, 1, 0, 20, 3)
	if err != nil || a != b {
		t.Errorf("OIDFromArcs = %q, %v; want %q", b, err, a)
	}
}
