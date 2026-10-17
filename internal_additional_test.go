package tcap

import (
	"bytes"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

func TestInternalExternalEncodings(t *testing.T) {
	for _, encoding := range []runtime.ExternalEncoding{runtime.ExternalSingleASN1Type, runtime.ExternalOctetAligned, runtime.ExternalArbitrary} {
		e := External{DirectReference: "1.2", Encoding: encoding}
		switch encoding {
		case runtime.ExternalSingleASN1Type:
			e.SingleASN1Type = []byte{5, 0}
		case runtime.ExternalOctetAligned:
			e.OctetAligned = []byte{1, 2, 3}
		case runtime.ExternalArbitrary:
			e.Arbitrary = runtime.BitString{Bytes: []byte{0xa0}, BitLength: 3}
		}
		for _, msg := range []Message{
			&Begin{OTID: TransactionID{1}, Dialogue: &Dialogue{Opaque: &e}},
			&Continue{OTID: TransactionID{1}, DTID: TransactionID{2}, Dialogue: NewAcceptDialogue("1.2", []External{e})},
			&End{DTID: TransactionID{2}, Dialogue: NewAcceptDialogue("1.2", []External{e})},
			&Abort{DTID: TransactionID{2}, Dialogue: NewUserAbortDialogue([]External{e})},
			&Unidirectional{Components: []Component{{Invoke: &Invoke{OpCode: LocalCode(1)}}}, Dialogue: &Dialogue{Unidirectional: &AUDT{ApplicationContextName: "1.2", UserInformation: []External{e}}}},
		} {
			out, err := msg.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			m, err := Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(msg, m) {
				t.Fatalf("round trip changed %T", msg)
			}
		}
		bad := cloneExternal(e)
		switch encoding {
		case runtime.ExternalSingleASN1Type:
			bad.OctetAligned = []byte{1}
		case runtime.ExternalOctetAligned:
			bad.Arbitrary = runtime.BitString{Bytes: []byte{0}, BitLength: 1}
		case runtime.ExternalArbitrary:
			bad.SingleASN1Type = []byte{5, 0}
		}
		if _, err := internalWithDialogue(&Dialogue{Opaque: &bad}).Marshal(); !errors.Is(err, ErrExternalEncoding) {
			t.Fatal(err)
		}
	}
	e := internalExternal()
	e.DirectReference = ""
	if _, err := internalWithDialogue(&Dialogue{Opaque: &e}).Marshal(); !errors.Is(err, ber.ErrInvalidValue) {
		t.Fatal(err)
	}
	e.IndirectReference = big.NewInt(1)
	data, err := internalWithDialogue(&Dialogue{Opaque: &e}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(data)
	if err != nil || m.(*Begin).Dialogue.Opaque.DirectReference != "" {
		t.Fatalf("%v", err)
	}
}

func TestInternalDialoguePlacementMatrix(t *testing.T) {
	diagnostics := NewAcceptDialogue("1.2", nil).Response.ResultSourceDiagnostic
	dialogues := []*Dialogue{
		{Request: &AARQ{ApplicationContextName: "1.2"}}, NewAcceptDialogue("1.2", nil), NewRejectDialogue("1.2", diagnostics, nil),
		NewUserAbortDialogue(nil), {Unidirectional: &AUDT{ApplicationContextName: "1.2"}},
	}
	for mi := 0; mi < 5; mi++ {
		for di, d := range dialogues {
			var m Message
			switch mi {
			case 0:
				m = &Begin{OTID: TransactionID{1}, Dialogue: d}
			case 1:
				m = &Continue{OTID: TransactionID{1}, DTID: TransactionID{2}, Dialogue: d}
			case 2:
				m = &End{DTID: TransactionID{2}, Dialogue: d}
			case 3:
				m = &Abort{DTID: TransactionID{2}, Dialogue: d}
			case 4:
				m = &Unidirectional{Components: []Component{{Invoke: &Invoke{OpCode: LocalCode(1)}}}, Dialogue: d}
			}
			allowed := mi == 0 && di == 0 || (mi == 1 || mi == 2) && di == 1 || mi == 3 && (di == 2 || di == 3) || mi == 4 && di == 4
			_, err := m.Marshal()
			if (err == nil) != allowed {
				t.Fatalf("sender %d/%d: %v", mi, di, err)
			}
			dp, err := encodeDialogue(d)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := dp.MarshalBER()
			if err != nil {
				t.Fatal(err)
			}
			var raw []byte
			switch mi {
			case 0:
				raw = internalTLV(0x62, []byte{0x48, 1, 1}, encoded)
			case 1:
				raw = internalTLV(0x65, []byte{0x48, 1, 1}, []byte{0x49, 1, 2}, encoded)
			case 2:
				raw = internalTLV(0x64, []byte{0x49, 1, 2}, encoded)
			case 3:
				raw = internalTLV(0x67, []byte{0x49, 1, 2}, encoded)
			case 4:
				raw = internalTLV(0x61, encoded, []byte{0x6c, 8, 0xa1, 6, 2, 1, 0, 2, 1, 1})
			}
			_, err = Parse(raw)
			if (err == nil) != allowed {
				t.Fatalf("receiver %d/%d: %v", mi, di, err)
			}
			if err != nil {
				var pe *ParseError
				if !errors.As(err, &pe) || pe.Portion != PortionDialogue {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestInternalProtocolVersions(t *testing.T) {
	for _, version := range []*runtime.BitString{nil, ProtocolVersion1(), {Bytes: []byte{0x80, 0}, BitLength: 16}, {Bytes: []byte{0x80}, BitLength: 8}} {
		d := NewAcceptDialogue("1.2", nil)
		d.Response.ProtocolVersion = version
		if _, err := (&End{DTID: TransactionID{1}, Dialogue: d}).Marshal(); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []*runtime.BitString{{}, {Bytes: []byte{0x40}, BitLength: 2}, {Bytes: []byte{0xc0}, BitLength: 2}, {Bytes: []byte{0x80, 0x80}, BitLength: 9}} {
		d := NewAcceptDialogue("1.2", nil)
		d.Response.ProtocolVersion = version
		if _, err := (&End{DTID: TransactionID{1}, Dialogue: d}).Marshal(); !errors.Is(err, ErrUnsupportedProtocolVersion) {
			t.Fatal(err)
		}
	}
	v := &runtime.BitString{Bytes: []byte{0xc0}, BitLength: 2}
	for _, m := range []Message{
		&Begin{OTID: TransactionID{1}, Dialogue: &Dialogue{Request: &AARQ{ProtocolVersion: v, ApplicationContextName: "1.2"}}},
		&Unidirectional{Components: []Component{{Invoke: &Invoke{OpCode: LocalCode(1)}}}, Dialogue: &Dialogue{Unidirectional: &AUDT{ProtocolVersion: v, ApplicationContextName: "1.2"}}},
	} {
		out, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(out)
		if err != nil || !reflect.DeepEqual(m, back) {
			t.Fatal(err)
		}
	}
}

func TestInternalDiagnosticOwnership(t *testing.T) {
	dp := internalDialogueBytes(t, internalRawRequest(nil), runtime.ExternalSingleASN1Type, wire.DialogueAsId())
	good := internalTLV(0xa1, []byte{2, 1, 1}, []byte{2, 1, 2}, []byte{4, 1, 9})
	bad := internalTLV(0xa1, []byte{2, 1, 3}, []byte{0x81, 0}, []byte{2, 1, 2})
	data := internalTLV(0x62, []byte{0x48, 1, 1}, dp, internalTLV(0x6c, good, bad, good))
	_, err := Parse(data)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Dialogue == nil || len(pe.Components) != 1 || pe.InvokeID == nil || *pe.InvokeID != 3 {
		t.Fatalf("%+v", pe)
	}
	for i := range data {
		data[i] = 0
	}
	if pe.OTID.String() != "01" || pe.Dialogue.Request.ApplicationContextName != "1.2" || !bytes.Equal(pe.Components[0].Invoke.Parameter, []byte{4, 1, 9}) {
		t.Fatal("diagnostic aliases input")
	}
	for _, badID := range [][]byte{{5, 0}, {2, 2, 0, 0x80}, {4, 1, 3}, {2, 2, 0, 3}} {
		_, err := Parse(internalRawBegin(internalTLV(0xa5, badID)))
		if !errors.As(err, &pe) || pe.InvokeID != nil {
			t.Fatalf("%x: %+v", badID, pe)
		}
	}
}

func TestInternalConversionCopies(t *testing.T) {
	parameter := []byte{4, 1, 9}
	ros := wire.NewComponentPortionElemBasicROSBoundInvoke(wire.ComponentPortionElemBasicROSInvokeBound{InvokeId: wire.NewTCInvokeIdSetPresent(1), Opcode: wire.NewCodeLocal(big.NewInt(2)), Argument: &runtime.RawValue{Bytes: parameter}})
	c, err := decodeComponent(wire.NewComponentPortionElemBoundBasicROS(ros), "Components[0]", nil)
	if err != nil {
		t.Fatal(err)
	}
	parameter[2] = 7
	if c.Invoke.Parameter[2] != 9 {
		t.Fatal("decoded component aliases wire value")
	}
	w, err := encodeComponents([]Component{c})
	if err != nil {
		t.Fatal(err)
	}
	c.Invoke.Parameter[2] = 8
	if w.Values[0].BasicROS.Invoke.Argument.Bytes[2] != 9 {
		t.Fatal("wire component aliases public value")
	}
	ref := big.NewInt(3)
	descriptor := "description"
	raw := runtime.External{DirectReference: runtime.MustObjectIdentifier("1.2"), IndirectReference: ref, DataValueDescriptor: &descriptor,
		Encoding: runtime.ExternalArbitrary, Arbitrary: runtime.BitString{Bytes: []byte{0x80}, BitLength: 1}}
	e, err := decodeExternal(raw)
	if err != nil {
		t.Fatal(err)
	}
	ref.SetInt64(5)
	descriptor = "changed"
	raw.Arbitrary.Bytes[0] = 0
	if e.IndirectReference.Int64() != 3 || *e.DataValueDescriptor != "description" || e.Arbitrary.Bytes[0] != 0x80 {
		t.Fatal("decoded EXTERNAL aliases wire value")
	}
	encoded, err := encodeExternal(e, "External")
	if err != nil {
		t.Fatal(err)
	}
	e.IndirectReference.SetInt64(7)
	*e.DataValueDescriptor = "changed"
	e.Arbitrary.Bytes[0] = 0
	if encoded.IndirectReference.Int64() != 3 || *encoded.DataValueDescriptor != "description" || encoded.Arbitrary.Bytes[0] != 0x80 {
		t.Fatal("encoded EXTERNAL aliases public value")
	}
}
