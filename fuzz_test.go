package tcap_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// FuzzParse: Parse never panics and never changes its input; every error is
// a *tcap.ParseError; a parsed message marshals, unless it breaks a rule
// that only the sender applies (contract 4.2: the protocol-version of an
// AARQ or AUDT and the user information of a provider ABRT are accepted on
// receipt); the marshalled form parses back to the same message, and
// marshals again to the same octets.
func FuzzParse(f *testing.F) {
	addParseSeeds(f)
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

// FuzzParseError: strict, tolerant and under tight decode limits, every
// error of Parse is a *tcap.ParseError of one line with one package prefix,
// whose context agrees with its documentation (ITU-T Q.774 (06/97) Tables 5
// and 7): a component index only in the component portion, with exactly the
// valid components that precede it; no component context otherwise; IDs
// within their constraints unless tolerated. Nothing Parse returns aliases
// its input.
func FuzzParseError(f *testing.F) {
	addParseSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, set := range []struct {
			name     string
			tolerant bool
			limits   *ber.DecodeLimits
		}{
			{"strict", false, nil},
			{"tolerant", true, nil},
			{"limits", false, &ber.DecodeLimits{MaxDepth: 4, MaxElements: 8, MaxWork: 64}},
		} {
			var opts []tcap.ParseOption
			if set.tolerant {
				opts = append(opts, tcap.WithConstraintTolerance(&ber.ViolationLog{}))
			}
			if set.limits != nil {
				opts = append(opts, tcap.WithDecodeLimits(*set.limits))
			}
			input := bytes.Clone(data)
			msg, err := tcap.Parse(input, opts...)
			if err == nil {
				out, merr := msg.Marshal()
				for i := range input {
					input[i] ^= 0xff
				}
				if out2, merr2 := msg.Marshal(); merr == nil && (merr2 != nil || !bytes.Equal(out, out2)) {
					t.Fatalf("%s: the parsed message of %x aliases its input", set.name, data)
				}
				continue
			}
			var pe *tcap.ParseError
			if !errors.As(err, &pe) || pe.Err == nil {
				t.Fatalf("%s: %x: error %T %v", set.name, data, err, err)
			}
			if text := pe.Error(); strings.Count(text, "tcap:") != 1 || strings.ContainsAny(text, "\r\n") {
				t.Fatalf("%s: %x: Error() = %q", set.name, data, text)
			}
			switch pe.Portion {
			case tcap.PortionTransaction, tcap.PortionDialogue, tcap.PortionComponent:
			default:
				t.Fatalf("%s: %x: Portion %q", set.name, data, pe.Portion)
			}
			if pe.ComponentIndex >= 0 {
				if pe.Portion != tcap.PortionComponent || len(pe.Components) != pe.ComponentIndex || pe.ComponentIndex == 0 && pe.Components != nil {
					t.Fatalf("%s: %x: component %d in %s with %d preceding", set.name, data, pe.ComponentIndex, pe.Portion, len(pe.Components))
				}
			} else if pe.ComponentIndex != -1 || pe.ComponentType != "" || pe.InvokeID != nil || pe.Dialogue != nil || pe.Components != nil {
				t.Fatalf("%s: %x: component context without a component: %+v", set.name, data, pe)
			}
			if !set.tolerant {
				for _, id := range []tcap.TransactionID{pe.OTID, pe.DTID} {
					if id != nil && (len(id) < 1 || len(id) > 4) {
						t.Fatalf("%s: %x: transaction ID %x", set.name, data, []byte(id))
					}
				}
				if pe.InvokeID != nil && (*pe.InvokeID < -128 || *pe.InvokeID > 127) {
					t.Fatalf("%s: %x: invoke ID %d", set.name, data, *pe.InvokeID)
				}
			}
			otid, dtid := pe.OTID.String(), pe.DTID.String()
			for i := range input {
				input[i] ^= 0xff
			}
			if pe.OTID.String() != otid || pe.DTID.String() != dtid {
				t.Fatalf("%s: %x: transaction IDs alias the input", set.name, data)
			}
		}
	})
}

// addParseSeeds adds the corpus, the captures and the inputs of past
// findings.
func addParseSeeds(f *testing.F) {
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
		"62174804010203046c0fa103020105a10802010602012d2500",
		"620948006c05a103020105",
		"63804f004e000000480101",
		"62084801014f00480102",
		"650b4801014901024f00490103",
		"620f4804010203046c05a1030201054f00",
		"62134804010203046c0ba109020200c8810002012d",
	} {
		f.Add(hx(s))
	}
}

// FuzzOID exercises this package's OID/error and uint64-view boundaries.
// Wide valid OIDs round-trip through a TCAP global code as well.
func FuzzOID(f *testing.F) {
	for _, c := range validOIDs {
		f.Add(c.s)
	}
	for _, s := range invalidOIDs {
		f.Add(s)
	}
	for _, s := range wideOIDs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		oid, err := tcap.ParseOID(s)
		if err != nil {
			if !errors.Is(err, tcap.ErrInvalidOID) && !errors.Is(err, runtime.ErrOIDTextLimit) {
				t.Fatalf("ParseOID(%q): %v", s, err)
			}
			return
		}
		if string(oid) != s {
			t.Fatalf("ParseOID(%q) = %q", s, oid)
		}
		arcs, err := oid.Arcs()
		if err == nil {
			back, err := tcap.OIDFromArcs(arcs...)
			if err != nil || back != oid {
				t.Fatalf("arcs round trip: %q, %v", back, err)
			}
		} else if !errors.Is(err, tcap.ErrUnrepresentableValue) {
			t.Fatal(err)
		}
		m := &tcap.Begin{OTID: tcap.TransactionID{1}, Components: []tcap.Component{{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.GlobalCode(oid)}}}}
		out, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		back, err := tcap.Parse(out)
		if err != nil || back.(*tcap.Begin).Components[0].Invoke.OpCode != tcap.GlobalCode(oid) {
			t.Fatalf("global OID round trip: %v, %v", back, err)
		}
	})
}
