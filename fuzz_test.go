package tcap_test

import (
	"bytes"
	"errors"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// FuzzParse: Parse never panics and never changes its input; every error is
// a *tcap.ParseError; a parsed message marshals, unless it breaks a rule
// that only the sender applies (contract 4.2: the protocol-version of an
// AARQ or AUDT and the user information of a provider ABRT are accepted on
// receipt); the marshalled form parses back to the same message, and
// marshals again to the same octets.
func FuzzParse(f *testing.F) {
	for _, v := range loadCorpus(f) {
		f.Add(hx(v.Hex))
	}
	for _, c := range loadCaptures(f) {
		f.Add(hx(c.Hex))
	}
	for _, s := range []string{
		parseErrorContinueHex,
		"621c4804010203046b14281206032a030402010507036162638103010203",
		"62134804010203046b0b280906032a0304820204f0",
		"67114904050607086b092807020107a0020500",
		"62374804010203046b1e281c0607001186050101018111600f80020780a1090607040000010014036c0fa10d02010102012d30050403010203",
		"62414804010203046b802880060700118605010101a080608080020780a180060704000001001403000000000000000000006c0fa10d02010102012d30050403010203",
		"621968060404010203046c0fa10d02010102012d30050403010203",
		"672d4904050607086b252823060700118605010101a0186416800101be11280f060704000001010101a004a4028000",
		"62374804010203046b1e281c060700118605010101a011600f80020640a1090607040000010014036c0fa10d02010102012d30050403010203",
	} {
		f.Add(hx(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		input := bytes.Clone(data)
		msg, err := tcap.Parse(data)
		if !bytes.Equal(data, input) {
			t.Fatalf("Parse changed its input")
		}
		if err != nil {
			if msg != nil {
				t.Fatalf("Parse returned a message with error %v", err)
			}
			pe, ok := err.(*tcap.ParseError)
			if !ok {
				t.Fatalf("error %T is not *tcap.ParseError: %v", err, err)
			}
			if pe.Error() == "" {
				t.Fatal("ParseError.Error() is empty")
			}
			return
		}
		if msg == nil {
			t.Fatal("Parse returned neither a message nor an error")
		}
		out, err := msg.Marshal()
		if err != nil {
			if errors.Is(err, tcap.ErrUnsupportedProtocolVersion) || errors.Is(err, tcap.ErrUnexpectedUserInformation) {
				return
			}
			t.Fatalf("Marshal of a parsed message %x: %v", data, err)
		}
		again, err := tcap.Parse(out)
		if err != nil {
			t.Fatalf("Parse(Marshal(%x)) = %v; Marshal gave %x", data, err, out)
		}
		assertSameMessage(t, msg, again)
		out2, err := again.Marshal()
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatalf("Marshal is not stable: %x then %x, %v", out, out2, err)
		}
	})
}

// FuzzOID: ParseOID never panics, reports only its two errors, and an
// accepted OID is exactly its input, follows the rules of oid.go and
// round-trips through Arcs and OIDFromArcs.
func FuzzOID(f *testing.F) {
	for _, c := range validOIDs {
		f.Add(c.s)
	}
	for _, s := range invalidOIDs {
		f.Add(s)
	}
	for _, s := range unrepresentableOIDs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		oid, err := tcap.ParseOID(s)
		if err != nil {
			invalid, unrepresentable := errors.Is(err, tcap.ErrInvalidOID), errors.Is(err, tcap.ErrUnrepresentableValue)
			if invalid == unrepresentable {
				t.Fatalf("ParseOID(%q) error %v: want exactly one of ErrInvalidOID, ErrUnrepresentableValue", s, err)
			}
			if _, err2 := tcap.OID(s).Arcs(); errors.Is(err2, tcap.ErrInvalidOID) != invalid || errors.Is(err2, tcap.ErrUnrepresentableValue) != unrepresentable {
				t.Fatalf("OID(%q).Arcs() error %v differs from ParseOID error %v", s, err2, err)
			}
			return
		}
		if string(oid) != s {
			t.Fatalf("ParseOID(%q) = %q", s, oid)
		}
		arcs, err := oid.Arcs()
		if err != nil {
			t.Fatalf("Arcs(%q): %v", s, err)
		}
		if len(arcs) < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) || (arcs[0] == 2 && arcs[1] > ^uint64(0)-80) {
			t.Fatalf("ParseOID accepted %q with arcs %v", s, arcs)
		}
		back, err := tcap.OIDFromArcs(arcs...)
		if err != nil || back != oid {
			t.Fatalf("OIDFromArcs(%v) = %q, %v; want %q", arcs, back, err, oid)
		}
	})
}
