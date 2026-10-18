package tcap

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func internalTLV(tag byte, children ...[]byte) []byte {
	v := bytes.Join(children, nil)
	out := []byte{tag}
	out = append(out, ber.EncodeLength(len(v))...)
	return append(out, v...)
}

func internalRawBegin(components ...[]byte) []byte {
	return internalTLV(0x62, internalTLV(0x48, []byte{1}), internalTLV(0x6c, components...))
}

func internalDialogueBytes(t *testing.T, pdu []byte, encoding runtime.ExternalEncoding, asid runtime.ObjectIdentifier) []byte {
	t.Helper()
	id, err := ber.EncodeObjectIdentifier(asid)
	if err != nil {
		t.Fatal(err)
	}
	var value []byte
	switch encoding {
	case runtime.ExternalSingleASN1Type:
		value = internalTLV(0xa0, pdu)
	case runtime.ExternalOctetAligned:
		value = internalTLV(0x81, pdu)
	case runtime.ExternalArbitrary:
		value = internalTLV(0x82, []byte{0}, pdu)
	}
	return internalTLV(0x6b, internalTLV(0x28, id, value))
}

func internalRawRequest(version []byte, ui ...[]byte) []byte {
	acn := internalTLV(0xa1, []byte{6, 1, 42})
	parts := [][]byte{version, acn}
	if ui != nil {
		parts = append(parts, internalTLV(0xbe, ui...))
	}
	return internalTLV(0x60, parts...)
}

func TestInternalReceiverRules(t *testing.T) {
	id, code := []byte{2, 1, 1}, []byte{2, 1, 3}
	large := []byte{2, 9, 0, 0x80, 0, 0, 0, 0, 0, 0, 0}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"invoke-null", internalRawBegin(internalTLV(0xa1, []byte{5, 0}, code)), nil},
		{"result-last-null", internalRawBegin(internalTLV(0xa2, []byte{5, 0})), nil},
		{"result-not-last-null", internalRawBegin(internalTLV(0xa7, []byte{5, 0})), nil},
		{"error-null", internalRawBegin(internalTLV(0xa3, []byte{5, 0}, code)), nil},
		{"linked-null", internalRawBegin(internalTLV(0xa1, id, []byte{0x81, 0}, code)), nil},
		{"invoke-overflow", internalRawBegin(internalTLV(0xa1, large, code)), ber.ErrInvalidValue},
		{"linked-overflow", internalRawBegin(internalTLV(0xa1, id, internalTLV(0x80, large[2:]), code)), ber.ErrInvalidValue},
		{"code-overflow", internalRawBegin(internalTLV(0xa1, id, large)), ErrUnrepresentableValue},
		{"result-code-overflow", internalRawBegin(internalTLV(0xa2, id, internalTLV(0x30, large, []byte{5, 0}))), ErrUnrepresentableValue},
		{"error-code-overflow", internalRawBegin(internalTLV(0xa3, id, large)), ErrUnrepresentableValue},
		{"reject-overflow", internalRawBegin(internalTLV(0xa4, large, []byte{0x80, 1, 0})), ber.ErrInvalidValue},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.data)
			var pe *ParseError
			var ce *ber.ValidationError
			wantCause := errors.Is(err, tc.want)
			if tc.want == nil {
				wantCause = errors.As(err, &ce)
			}
			if !errors.As(err, &pe) || !wantCause || pe.Portion != PortionComponent || pe.ComponentIndex != 0 {
				t.Fatalf("%v", err)
			}
			if bytes.Contains([]byte(tc.name), []byte("overflow")) && (tc.name == "invoke-overflow" || tc.name == "reject-overflow") && pe.InvokeID != nil {
				t.Fatal("overflow ID derived")
			}
		})
	}
	for _, n := range []int64{-129, 128} {
		encoded := ber.EncodeInteger(n)
		for _, component := range [][]byte{
			internalTLV(0xa1, encoded, code), internalTLV(0xa1, id, internalTLV(0x80, encoded[2:]), code),
			internalTLV(0xa2, encoded), internalTLV(0xa7, encoded), internalTLV(0xa3, encoded, code), internalTLV(0xa4, encoded, []byte{0x80, 1, 0}),
		} {
			_, err := Parse(internalRawBegin(component))
			var ce *ber.ValidationError
			if !errors.As(err, &ce) {
				t.Fatalf("%x: %v", component, err)
			}
			var log ber.ViolationLog
			m, err := Parse(internalRawBegin(component), WithTolerance(&log))
			if err != nil || len(log.Snapshot()) != 1 {
				t.Fatalf("tolerance: %v %+v", err, log.Snapshot())
			}
			internalConstraint(t, m)
		}
	}
}

func TestInternalReceiverDialogue(t *testing.T) {
	for _, encoding := range []runtime.ExternalEncoding{runtime.ExternalSingleASN1Type, runtime.ExternalOctetAligned, runtime.ExternalArbitrary} {
		pdu := internalRawRequest([]byte{0x80, 2, 6, 0x40})
		data := internalTLV(0x62, []byte{0x48, 1, 1}, internalDialogueBytes(t, pdu, encoding, wire.DialogueAsId()))
		m, err := Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		request := m.(*Begin).Dialogue.Request
		if OffersVersion1(request.ProtocolVersion) || request.ProtocolVersion.BitLength != 2 || !bytes.Equal(request.ProtocolVersion.Bytes, []byte{0x40}) {
			t.Fatalf("version changed: %+v", request.ProtocolVersion)
		}
		if _, err := m.Marshal(); !errors.Is(err, ErrUnsupportedProtocolVersion) {
			t.Fatal(err)
		}
	}
	// Provider user information is legal on receive; Q.774 clause 3.2.2.1 limits senders.
	pdu := internalTLV(0x64, []byte{0x80, 1, 1}, []byte{0xbe, 0})
	m, err := Parse(internalTLV(0x67, []byte{0x49, 1, 1}, internalDialogueBytes(t, pdu, runtime.ExternalSingleASN1Type, wire.DialogueAsId())))
	if err != nil {
		t.Fatal(err)
	}
	if m.(*Abort).Dialogue.Abort.UserInformation == nil {
		t.Fatal("empty UI lost")
	}
	if _, err := m.Marshal(); !errors.Is(err, ErrUnexpectedUserInformation) {
		t.Fatal(err)
	}
	for _, pdu := range [][]byte{{5, 0}, internalTLV(0x60)} {
		_, err := Parse(internalTLV(0x62, []byte{0x48, 1, 1}, internalDialogueBytes(t, pdu, runtime.ExternalSingleASN1Type, wire.DialogueAsId())))
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Portion != PortionDialogue {
			t.Fatal(err)
		}
	}
	accept := internalTLV(0x61, []byte{0x80, 2, 6, 0xc0}, []byte{0xa1, 3, 6, 1, 42}, []byte{0xa2, 3, 2, 1, 0}, []byte{0xa3, 5, 0xa1, 3, 2, 1, 0})
	_, err = Parse(internalTLV(0x64, []byte{0x49, 1, 1}, internalDialogueBytes(t, accept, runtime.ExternalSingleASN1Type, wire.DialogueAsId())))
	if !errors.Is(err, ErrUnsupportedProtocolVersion) {
		t.Fatal(err)
	}
	// A non-octet-aligned known PDU is a dialogue error, not opaque data.
	dp := internalDialogueBytes(t, []byte{0x60, 0}, runtime.ExternalArbitrary, wire.DialogueAsId())
	dp[len(dp)-3] = 1
	_, err = Parse(internalTLV(0x62, []byte{0x48, 1, 1}, dp))
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Portion != PortionDialogue {
		t.Fatal(err)
	}
}

func TestInternalToleranceStaging(t *testing.T) {
	for _, v := range internalVectors(t, "testdata/corpus.json") {
		if v.ID != "negative-otid-0" && v.ID != "negative-otid-5" && v.ID != "negative-invokeid-128" && v.ID != "negative-invokeid--129" && v.ID != "negative-empty-components" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			var log ber.ViolationLog
			m, err := Parse(internalHex(t, v.Hex), WithTolerance(&log))
			if err != nil {
				t.Fatal(err)
			}
			if len(log.Snapshot()) != 1 {
				t.Fatalf("violations: %+v", log.Snapshot())
			}
			internalConstraint(t, m)
		})
	}
	var log ber.ViolationLog
	good := internalRawBegin(internalTLV(0xa1, ber.EncodeInteger(128), []byte{2, 1, 1}))
	if _, err := Parse(good, WithTolerance(&log)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append(bytes.Clone(good), 5, 0),
		internalRawBegin(internalTLV(0xa1, ber.EncodeInteger(128), []byte{0x81, 0}, []byte{2, 1, 1})),
		internalRawBegin(internalTLV(0xa1, ber.EncodeInteger(128), []byte{2, 1, 1}), internalTLV(0xa1, []byte{5, 0}, []byte{2, 1, 1})),
	} {
		if _, err := Parse(bad, WithTolerance(&log)); err == nil {
			t.Fatal("bad message accepted")
		}
		if len(log.Snapshot()) != 1 {
			t.Fatalf("failed call published reports: %+v", log.Snapshot())
		}
	}
	if _, err := Parse(good, WithTolerance(nil)); err == nil {
		t.Fatal("nil tolerance destination accepted")
	}
}

func TestInternalInspection(t *testing.T) {
	prefix := internalTLV(0xa1, []byte{2, 1, 1}, []byte{2, 1, 2})
	bad := internalTLV(0xa5, []byte{2, 1, 3})
	_, err := Parse(internalRawBegin(prefix, bad, prefix))
	var pe *ParseError
	if !errors.As(err, &pe) || !errors.Is(err, ErrUnrecognizedComponent) || pe.MessageType != MessageTypeBegin || pe.OTID.String() != "01" || pe.ComponentIndex != 1 || pe.InvokeID == nil || *pe.InvokeID != 3 || len(pe.Components) != 1 {
		t.Fatalf("%+v", pe)
	}
	if pe.Components[0].Invoke.OpCode != LocalCode(2) {
		t.Fatal("prefix corrupted")
	}
	unknown := internalTLV(0x66, []byte{0x48, 1, 1}, []byte{0x49, 1, 2})
	_, err = Parse(unknown)
	if !errors.As(err, &pe) || !errors.Is(err, ErrUnrecognizedMessageType) || pe.MessageType != "" || pe.OTID.String() != "01" || pe.DTID.String() != "02" {
		t.Fatalf("%+v", pe)
	}
	for _, data := range [][]byte{
		internalTLV(0x65, []byte{0x49, 1, 2}, []byte{0x48, 1, 1}),
		internalTLV(0x62, []byte{0x48, 1, 1}, []byte{0x48, 1, 2}),
		internalTLV(0x65, []byte{0x48, 1, 1}),
		internalTLV(0x62, []byte{0x48, 1, 1}, []byte{0x6c, 1, 0xa1}),
	} {
		_, err := Parse(data)
		if !errors.As(err, &pe) {
			t.Fatal(err)
		}
	}
	if _, err := Parse(nil); !errors.Is(err, ErrEmptyData) {
		t.Fatal(err)
	}
	for _, limits := range []ber.DecodeLimits{{MaxDepth: 1}, {MaxElements: 1}, {MaxWork: 1}, {MaxDepth: -1}} {
		_, err := Parse(internalRawBegin(prefix), WithDecodeLimits(limits))
		if err == nil {
			t.Fatalf("limits %+v not applied", limits)
		}
	}
	if _, err := Parse(internalRawBegin(prefix), WithDecodeLimits(ber.DecodeLimits{})); err != nil {
		t.Fatal(err)
	}
	if got := (&ParseError{MessageType: MessageTypeBegin, Portion: PortionComponent, ComponentIndex: 2, Err: nil}).Error(); got != "tcap: parse Begin: component portion component 2: <nil>" {
		t.Fatal(got)
	}
}

func TestInternalUnknownMessageAndComponent(t *testing.T) {
	_, err := Parse(internalHex(t, "660a4801016c05a503020103"))
	if !errors.Is(err, ErrUnrecognizedMessageType) || errors.Is(err, ErrUnrecognizedComponent) {
		t.Fatalf("unknown message must fail in the transaction portion: %v", err)
	}
}

func TestInternalRecipesAndOwnership(t *testing.T) {
	ref := big.NewInt(9)
	desc := "descriptor"
	external := internalExternal()
	external.IndirectReference = ref
	external.DataValueDescriptor = &desc
	ui := []External{external}
	d := NewAcceptDialogue("1.2", ui)
	if d.Response.Result.BigInt().Sign() != 0 || d.Response.ResultSourceDiagnostic.DialogueServiceUser == nil || !OffersVersion1(d.Response.ProtocolVersion) {
		t.Fatal("bad accept recipe")
	}
	ref.SetInt64(10)
	desc = "changed"
	ui[0].SingleASN1Type[0] = 4
	if d.Response.UserInformation[0].IndirectReference.Int64() != 9 || *d.Response.UserInformation[0].DataValueDescriptor != "descriptor" || d.Response.UserInformation[0].SingleASN1Type[0] != 5 {
		t.Fatal("recipe aliases arguments")
	}
	if NewAcceptDialogue("1.2", nil).Response.UserInformation != nil || NewAcceptDialogue("1.2", []External{}).Response.UserInformation == nil {
		t.Fatal("nil/empty UI lost")
	}
	if NewUserAbortDialogue([]External{}).Abort.UserInformation == nil || NewProviderAbortDialogue().Abort.UserInformation != nil {
		t.Fatal("abort recipe")
	}
	diagnostic := wire.AssociateSourceDiagnosticDialogueServiceUserValueNullValue()
	reject := NewRejectDialogue("1.2", ResultSourceDiagnostic{DialogueServiceUser: &diagnostic}, nil)
	diagnostic = wire.NewAssociateSourceDiagnosticDialogueServiceUserValueInt64(2)
	if reject.Response.Result.BigInt().Int64() != 1 || reject.Response.ResultSourceDiagnostic.DialogueServiceUser.BigInt().Sign() != 0 {
		t.Fatal("reject recipe")
	}
	v1, v2 := ProtocolVersion1(), ProtocolVersion1()
	v1.Bytes[0] = 0
	if !OffersVersion1(v2) || !OffersVersion1(nil) || OffersVersion1(&runtime.BitString{}) {
		t.Fatal("version recipe")
	}
	for _, ui := range [][]External{nil, {}, {internalExternal()}} {
		m := &Begin{OTID: TransactionID{1}, Dialogue: &Dialogue{Request: &AARQ{ApplicationContextName: "1.2", UserInformation: ui}}, Components: []Component{{Invoke: &Invoke{InvokeID: 1, LinkedID: internalInt(2), OpCode: LocalCode(3), Parameter: []byte{4, 1, 9}}}}}
		out, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		if !internalSameMessage(m, parsed) {
			t.Fatalf("nil/empty or values changed: %#v", parsed)
		}
		original := bytes.Clone(out)
		m.OTID[0] = 8
		m.Components[0].Invoke.Parameter[2] = 8
		if !bytes.Equal(original, out) {
			t.Fatal("output aliases input")
		}
		before, err := parsed.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		for i := range out {
			out[i] = 0
		}
		after, err := parsed.Marshal()
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("parse aliases input")
		}
		for i := range before {
			before[i] = 0
		}
		again, err := parsed.Marshal()
		if err != nil || !bytes.Equal(again, after) {
			t.Fatal("marshal aliases parsed message")
		}
	}
	for _, components := range [][]Component{nil, {}} {
		var log ber.ViolationLog
		data := internalTLV(0x62, []byte{0x48, 1, 1})
		if components != nil {
			data = internalTLV(0x62, []byte{0x48, 1, 1}, []byte{0x6c, 0})
		}
		m, err := Parse(data, WithTolerance(&log))
		if err != nil {
			t.Fatal(err)
		}
		if (m.(*Begin).Components == nil) != (components == nil) {
			t.Fatal("nil/empty components lost")
		}
	}
}
