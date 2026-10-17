package tcap_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
)

func TestMarshalRejectsInvalidExternalBitStrings(t *testing.T) {
	for _, bits := range []runtime.BitString{{Bytes: []byte{0xff}, BitLength: 1}, {Bytes: []byte{0x80, 0}, BitLength: 1}, {Bytes: []byte{1}, BitLength: 0}} {
		for _, place := range []string{"opaque", "user information"} {
			t.Run(fmt.Sprintf("%s/%x/%d", place, bits.Bytes, bits.BitLength), func(t *testing.T) {
				ext := tcap.External{DirectReference: "1.2", Encoding: runtime.ExternalArbitrary, Arbitrary: bits}
				d := &tcap.Dialogue{Opaque: &ext}
				if place == "user information" {
					d = &tcap.Dialogue{Request: &tcap.AARQ{ApplicationContextName: "1.2", UserInformation: []tcap.External{ext}}}
				}
				before := bytes.Clone(bits.Bytes)
				_, err := (&tcap.Begin{OTID: tcap.TransactionID{1}, Dialogue: d}).Marshal()
				if !errors.Is(err, ber.ErrInvalidValue) {
					t.Fatalf("invalid caller BIT STRING: %v", err)
				}
				if !bytes.Equal(before, bits.Bytes) {
					t.Fatal("Marshal altered caller bits")
				}
			})
		}
	}
}

func TestParseRemarshalsReceivedUnusedBits(t *testing.T) {
	for _, text := range []string{
		tlv("62", "480101", tlv("6b", "280706012a820207ff")),
		tlv("62", "480101", dialoguePortion(hexDialogueAS, "6009800207ffa10306012a")),
		tlv("62", "480101", dialoguePortion(hexDialogueAS, tlv("60", "80020780", "a10306012a", tlv("be", "280706012a820207ff")))),
	} {
		data := hx(text)
		before := bytes.Clone(data)
		m, err := tcap.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		out, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte{0xff}) {
			t.Fatalf("padding retained: %x", out)
		}
		back, err := tcap.Parse(out)
		if err != nil || !reflect.DeepEqual(m, back) {
			t.Fatalf("received BIT STRING round trip: %v", err)
		}
		if !bytes.Equal(data, before) {
			t.Fatal("input changed")
		}
	}
}
