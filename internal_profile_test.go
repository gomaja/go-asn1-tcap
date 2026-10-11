package tcap

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

func TestInternalProfileBoundaries(t *testing.T) {
	id, code, param := []byte{2, 1, 1}, []byte{2, 1, 2}, []byte{5, 0}
	invoke := internalTLV(0xa1, id, code, param)
	tid := []byte{0x48, 1, 1}
	request := internalRawRequest([]byte{0x80, 2, 7, 0x80})
	dialogue := internalDialogueBytes(t, request, runtime.ExternalSingleASN1Type, wire.DialogueAsId())
	_, _, dialogueContent, _ := ber.DecodeTLV(dialogue)
	_, _, externalContent, _ := ber.DecodeTLV(dialogueContent)
	_, n, _, _ := ber.DecodeTLV(externalContent)
	reference, value := externalContent[:n], externalContent[n:]
	wrap := func(dp []byte) []byte { return internalTLV(0x62, tid, dp) }
	nonminimalUI := internalTLV(0x28, []byte{6, 1, 42}, internalTLV(0xa0, []byte{5, 0}))
	tests := []struct {
		name    string
		data    []byte
		portion Portion
		index   int
		want    error
	}{
		{"message", internalNonminimal(internalRawBegin(invoke)), PortionTransaction, -1, ErrNonMinimalLength},
		{"otid", internalTLV(0x62, internalNonminimal(tid)), PortionTransaction, -1, ErrNonMinimalLength},
		{"dtid", internalTLV(0x64, []byte{0x49, 0x81, 1, 1}), PortionTransaction, -1, ErrNonMinimalLength},
		{"cause", internalTLV(0x67, []byte{0x49, 1, 1}, []byte{0x4a, 0x81, 1, 0}), PortionTransaction, -1, ErrNonMinimalLength},
		{"component-portion", internalTLV(0x62, tid, internalNonminimal(internalTLV(0x6c, invoke))), PortionComponent, -1, ErrNonMinimalLength},
		{"component", internalRawBegin(internalNonminimal(invoke)), PortionComponent, 0, ErrNonMinimalLength},
		{"invoke-id", internalRawBegin(internalTLV(0xa1, internalNonminimal(id), code)), PortionComponent, 0, ErrNonMinimalLength},
		{"linked-id", internalRawBegin(internalTLV(0xa1, id, []byte{0x80, 0x81, 1, 1}, code)), PortionComponent, 0, ErrNonMinimalLength},
		{"code", internalRawBegin(internalTLV(0xa1, id, internalNonminimal(code))), PortionComponent, 0, ErrNonMinimalLength},
		{"argument", internalRawBegin(internalTLV(0xa1, id, code, internalNonminimal(param))), PortionComponent, 0, ErrNonMinimalLength},
		{"result-sequence", internalRawBegin(internalTLV(0xa2, id, internalNonminimal(internalTLV(0x30, code, param)))), PortionComponent, 0, ErrNonMinimalLength},
		{"result-code", internalRawBegin(internalTLV(0xa7, id, internalTLV(0x30, internalNonminimal(code), param))), PortionComponent, 0, ErrNonMinimalLength},
		{"result-parameter", internalRawBegin(internalTLV(0xa2, id, internalTLV(0x30, code, internalNonminimal(param)))), PortionComponent, 0, ErrNonMinimalLength},
		{"error-code", internalRawBegin(internalTLV(0xa3, id, internalNonminimal(code))), PortionComponent, 0, ErrNonMinimalLength},
		{"error-parameter", internalRawBegin(internalTLV(0xa3, id, code, internalNonminimal(param))), PortionComponent, 0, ErrNonMinimalLength},
		{"problem", internalRawBegin(internalTLV(0xa4, id, []byte{0x80, 0x81, 1, 0})), PortionComponent, 0, ErrNonMinimalLength},
		{"dialogue-portion", wrap(internalNonminimal(dialogue)), PortionDialogue, -1, ErrNonMinimalLength},
		{"external", wrap(internalTLV(0x6b, internalNonminimal(dialogueContent))), PortionDialogue, -1, ErrNonMinimalLength},
		{"direct-reference", wrap(internalTLV(0x6b, internalTLV(0x28, internalNonminimal(reference), value))), PortionDialogue, -1, ErrNonMinimalLength},
		{"indirect-reference", wrap(internalTLV(0x6b, internalTLV(0x28, reference, internalNonminimal(id), value))), PortionDialogue, -1, ErrNonMinimalLength},
		{"descriptor", wrap(internalTLV(0x6b, internalTLV(0x28, reference, []byte{7, 0x81, 1, 'a'}, value))), PortionDialogue, -1, ErrNonMinimalLength},
		{"single-wrapper", wrap(internalTLV(0x6b, internalTLV(0x28, reference, internalNonminimal(value)))), PortionDialogue, -1, ErrNonMinimalLength},
		{"pdu", wrap(internalDialogueBytes(t, internalNonminimal(request), runtime.ExternalSingleASN1Type, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"pdu-octets", wrap(internalDialogueBytes(t, internalNonminimal(request), runtime.ExternalOctetAligned, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"pdu-bits", wrap(internalDialogueBytes(t, internalNonminimal(request), runtime.ExternalArbitrary, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"version", wrap(internalDialogueBytes(t, internalRawRequest([]byte{0x80, 0x81, 2, 7, 0x80}), runtime.ExternalSingleASN1Type, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"acn-wrapper", wrap(internalDialogueBytes(t, internalTLV(0x60, internalNonminimal([]byte{0xa1, 3, 6, 1, 42})), runtime.ExternalSingleASN1Type, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"acn-value", wrap(internalDialogueBytes(t, internalTLV(0x60, internalTLV(0xa1, []byte{6, 0x81, 1, 42})), runtime.ExternalSingleASN1Type, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"user-info", wrap(internalDialogueBytes(t, internalTLV(0x60, []byte{0xa1, 3, 6, 1, 42}, internalNonminimal(internalTLV(0xbe, nonminimalUI))), runtime.ExternalSingleASN1Type, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"user-external", wrap(internalDialogueBytes(t, internalRawRequest(nil, internalNonminimal(nonminimalUI)), runtime.ExternalSingleASN1Type, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"user-single-value", wrap(internalDialogueBytes(t, internalRawRequest(nil, internalTLV(0x28, []byte{6, 1, 42}, internalTLV(0xa0, internalNonminimal(param)))), runtime.ExternalSingleASN1Type, wire.DialogueAsId())), PortionDialogue, -1, ErrNonMinimalLength},
		{"constructed-otid", internalTLV(0x62, internalTLV(0x68, []byte{4, 1, 1})), PortionTransaction, -1, ErrConstructedString},
		{"constructed-dtid", internalTLV(0x64, internalTLV(0x69, []byte{4, 1, 1})), PortionTransaction, -1, ErrConstructedString},
		{"constructed-version", wrap(internalDialogueBytes(t, internalRawRequest(internalTLV(0xa0, []byte{3, 2, 7, 0x80})), runtime.ExternalSingleASN1Type, wire.DialogueAsId())), PortionDialogue, -1, ErrConstructedString},
		{"constructed-octets", wrap(internalTLV(0x6b, internalTLV(0x28, []byte{6, 1, 42}, internalTLV(0xa1, []byte{4, 1, 7})))), PortionDialogue, -1, ErrConstructedString},
		{"constructed-arbitrary", wrap(internalTLV(0x6b, internalTLV(0x28, []byte{6, 1, 42}, internalTLV(0xa2, []byte{3, 2, 0, 7})))), PortionDialogue, -1, ErrConstructedString},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.data)
			var pe *ParseError
			if !errors.As(err, &pe) || !errors.Is(err, tc.want) || pe.Portion != tc.portion || pe.ComponentIndex != tc.index {
				t.Fatalf("got %v, want %v at %s/%d", err, tc.want, tc.portion, tc.index)
			}
		})
	}
}

func TestInternalProfileOpaqueAndIndefinite(t *testing.T) {
	// Nonminimal interior lengths and constructed strings belong to the TC-user.
	opaque := internalTLV(0x30, []byte{4, 0x81, 1, 7}, internalTLV(0x24, []byte{4, 1, 8}))
	for _, c := range []Component{
		{Invoke: &Invoke{OpCode: LocalCode(1), Parameter: opaque}},
		{ReturnResultLast: &ReturnResult{Result: &Result{OpCode: LocalCode(1), Parameter: opaque}}},
		{ReturnResultNotLast: &ReturnResult{Result: &Result{OpCode: LocalCode(1), Parameter: opaque}}},
		{ReturnError: &ReturnError{ErrorCode: LocalCode(1), Parameter: opaque}},
	} {
		data, err := internalBegin(c).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []*Dialogue{
		{Opaque: &External{DirectReference: "1.2", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: opaque}},
		{Request: &AARQ{ApplicationContextName: "1.2", UserInformation: []External{{DirectReference: "1.2", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: opaque}}}},
	} {
		data, err := internalWithDialogue(d).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err != nil {
			t.Fatal(err)
		}
	}
	for _, length := range []int{0, 1, 127, 128, 255, 256} {
		p := internalTLV(0x04, bytes.Repeat([]byte{7}, length))
		data, err := internalBegin(Component{Invoke: &Invoke{OpCode: LocalCode(1), Parameter: p}}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(data); err != nil {
			t.Fatal(err)
		}
		if length >= 128 {
			bad := internalRawBegin(internalTLV(0xa1, []byte{2, 1, 0}, []byte{2, 1, 1}, internalNonminimal(p)))
			if _, err := Parse(bad); !errors.Is(err, ErrNonMinimalLength) {
				t.Fatal(err)
			}
		}
	}
	indef := []byte{0x62, 0x80, 0x48, 1, 1, 0x6c, 0x80, 0xa1, 0x80, 2, 1, 0, 2, 1, 1, 0, 0, 0, 0, 0, 0}
	m, err := Parse(indef)
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Marshal()
	if err != nil || out[1] == 0x80 {
		t.Fatalf("%x %v", out, err)
	}
	// A definite opaque value may have arbitrary content that is not a TLV.
	if err := validateParameter([]byte{4, 3, 0xff, 0xff, 0xff}, "Parameter"); err != nil {
		t.Fatal(err)
	}
}

func FuzzInternalParse(f *testing.F) {
	for _, s := range []string{"", "62174804010203046c0fa10d02010102012d30050403010203", "62804804010203046c0fa10d02010102012d300504030102030000", "62084804010203046c00", "66174804010203046c0fa10d02010102012d30050403010203"} {
		var b []byte
		if s != "" {
			var err error
			b, err = hex.DecodeString(s)
			if err != nil {
				f.Fatal(err)
			}
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("%T", err)
			}
			return
		}
		out, err := m.Marshal()
		if err != nil {
			return
		} // Receiver-only accepted values may fail sender rules.
		if _, err := Parse(out); err != nil {
			t.Fatalf("round trip: %v", err)
		}
	})
}
