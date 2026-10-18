package tcap

import (
	"errors"
	"math"
	"strconv"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func internalBegin(c Component) Message {
	return &Begin{OTID: TransactionID{1}, Components: []Component{c}}
}
func internalWithDialogue(d *Dialogue) Message { return &Begin{OTID: TransactionID{1}, Dialogue: d} }
func internalInt(v int64) *int64               { return &v }
func internalExternal() External {
	return External{DirectReference: "1.2", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: []byte{5, 0}}
}

func TestInternalSenderSentinels(t *testing.T) {
	g := wire.GeneralProblemMistypedPDUValue()
	ip := wire.InvokeProblemMistypedArgumentValue()
	user := wire.AssociateSourceDiagnosticDialogueServiceUserValueNullValue()
	provider := wire.NewAssociateSourceDiagnosticDialogueServiceProviderValueInt64(0)
	cause := wire.NewPAbortCauseInt64(0)
	external := internalExternal()
	badExternal := external
	badExternal.Encoding = 0
	badSingle := external
	badSingle.SingleASN1Type = []byte{5, 0, 5, 0}
	badOID := external
	badOID.DirectReference = "1.40"
	tests := []struct {
		name string
		m    Message
		want error
		path string
	}{
		{"nil", (*Begin)(nil), ErrNilMessage, ""},
		{"component-none", internalBegin(Component{}), ErrComponentNoAlternative, "Components[0]"},
		{"component-multiple", internalBegin(Component{Invoke: &Invoke{}, Reject: &Reject{}}), ErrComponentMultipleAlternatives, "Components[0]"},
		{"code-none", internalBegin(Component{Invoke: &Invoke{}}), ErrCodeNoAlternative, "Components[0].Invoke.OpCode"},
		{"result-code-none", internalBegin(Component{ReturnResultLast: &ReturnResult{Result: &Result{}}}), ErrCodeNoAlternative, "Components[0].ReturnResultLast.Result.OpCode"},
		{"error-code-none", internalBegin(Component{ReturnError: &ReturnError{}}), ErrCodeNoAlternative, "Components[0].ReturnError.ErrorCode"},
		{"invalid-code-oid", internalBegin(Component{Invoke: &Invoke{OpCode: GlobalCode("1.40")}}), ErrInvalidOID, "Components[0].Invoke.OpCode"},
		{"problem-none", internalBegin(Component{Reject: &Reject{}}), ErrProblemNoAlternative, "Components[0].Reject.Problem"},
		{"problem-multiple", internalBegin(Component{Reject: &Reject{Problem: Problem{General: &g, Invoke: &ip}}}), ErrProblemMultipleAlternatives, "Components[0].Reject.Problem"},
		{"dialogue-none", internalWithDialogue(&Dialogue{}), ErrDialogueNoAlternative, "Dialogue"},
		{"dialogue-multiple", internalWithDialogue(&Dialogue{Request: &AARQ{}, Opaque: &external}), ErrDialogueMultipleAlternatives, "Dialogue"},
		{"placement", internalWithDialogue(NewProviderAbortDialogue()), ErrUnexpectedDialoguePDU, "Dialogue"},
		{"accepted-abort", &Abort{DTID: TransactionID{1}, Dialogue: NewAcceptDialogue("1.2", nil)}, ErrUnexpectedDialogueResult, "Dialogue.Response.Result"},
		{"rejected-end", &End{DTID: TransactionID{1}, Dialogue: NewRejectDialogue("1.2", ResultSourceDiagnostic{DialogueServiceUser: &user}, nil)}, ErrUnexpectedDialogueResult, "Dialogue.Response.Result"},
		{"diagnostic-none", &End{DTID: TransactionID{1}, Dialogue: &Dialogue{Response: &AARE{ApplicationContextName: "1.2"}}}, ErrResultSourceDiagnosticNoAlternative, "Dialogue.Response.ResultSourceDiagnostic"},
		{"diagnostic-multiple", &End{DTID: TransactionID{1}, Dialogue: &Dialogue{Response: &AARE{ApplicationContextName: "1.2", ResultSourceDiagnostic: ResultSourceDiagnostic{DialogueServiceUser: &user, DialogueServiceProvider: &provider}}}}, ErrResultSourceDiagnosticMultipleAlternatives, "Dialogue.Response.ResultSourceDiagnostic"},
		{"request-version", internalWithDialogue(&Dialogue{Request: &AARQ{ApplicationContextName: "1.2", ProtocolVersion: &runtime.BitString{Bytes: []byte{0x40}, BitLength: 2}}}), ErrUnsupportedProtocolVersion, "Dialogue.Request.ProtocolVersion"},
		{"response-version", &End{DTID: TransactionID{1}, Dialogue: &Dialogue{Response: &AARE{ApplicationContextName: "1.2", ProtocolVersion: &runtime.BitString{Bytes: []byte{0xc0}, BitLength: 2}}}}, ErrUnsupportedProtocolVersion, "Dialogue.Response.ProtocolVersion"},
		{"audt-version", &Unidirectional{Dialogue: &Dialogue{Unidirectional: &AUDT{ProtocolVersion: &runtime.BitString{}}}}, ErrUnsupportedProtocolVersion, "Dialogue.Unidirectional.ProtocolVersion"},
		{"provider-ui-empty", &Abort{DTID: TransactionID{1}, Dialogue: &Dialogue{Abort: &ABRT{AbortSource: wire.ABRTSourceDialogueServiceProviderValue(), UserInformation: []External{}}}}, ErrUnexpectedUserInformation, "Dialogue.Abort.UserInformation"},
		{"abort-reasons", &Abort{DTID: TransactionID{1}, Dialogue: NewProviderAbortDialogue(), PAbortCause: &cause}, ErrAbortMultipleReasons, "Dialogue"},
		{"external-choice", internalWithDialogue(&Dialogue{Opaque: &badExternal}), ErrExternalEncoding, "Dialogue.Opaque"},
		{"external-oid", internalWithDialogue(&Dialogue{Opaque: &badOID}), ErrInvalidOID, "Dialogue.Opaque.DirectReference"},
		{"external-single", internalWithDialogue(&Dialogue{Opaque: &badSingle}), ber.ErrExtraData, ""},
		{"parameter-empty", internalBegin(Component{Invoke: &Invoke{OpCode: LocalCode(1), Parameter: []byte{}}}), ber.ErrTruncated, ""},
		{"parameter-trailing", internalBegin(Component{ReturnError: &ReturnError{ErrorCode: LocalCode(1), Parameter: []byte{5, 0, 5, 0}}}), ber.ErrExtraData, ""},
		{"result-missing-parameter", internalBegin(Component{ReturnResultNotLast: &ReturnResult{Result: &Result{OpCode: LocalCode(1)}}}), ber.ErrTruncated, ""},
		{"application-context", internalWithDialogue(&Dialogue{Request: &AARQ{ApplicationContextName: "01.2"}}), ErrInvalidOID, "Dialogue.Request.ApplicationContextName"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.m.Marshal()
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			if test.path != "" {
				var fe *FieldError
				if !errors.As(err, &fe) || fe.Path != test.path {
					t.Fatalf("FieldError: %v", err)
				}
			}
		})
	}
	for _, nilMessage := range []Message{(*Continue)(nil), (*End)(nil), (*Abort)(nil), (*Unidirectional)(nil)} {
		if _, err := nilMessage.Marshal(); !errors.Is(err, ErrNilMessage) {
			t.Fatal(err)
		}
	}
}

func internalGeneralProblem() *wire.GeneralProblem {
	v := wire.GeneralProblemUnrecognizedPDUValue()
	return &v
}

func TestInternalSenderConstraints(t *testing.T) {
	idNames := []string{"Invoke.InvokeID", "Invoke.LinkedID", "ReturnResultLast.InvokeID", "ReturnResultNotLast.InvokeID", "ReturnError.InvokeID", "Reject.InvokeID"}
	for _, id := range []int64{-129, 128} {
		cases := []Component{
			{Invoke: &Invoke{InvokeID: id, OpCode: LocalCode(1)}},
			{Invoke: &Invoke{LinkedID: &id, OpCode: LocalCode(1)}},
			{ReturnResultLast: &ReturnResult{InvokeID: id}},
			{ReturnResultNotLast: &ReturnResult{InvokeID: id}},
			{ReturnError: &ReturnError{InvokeID: id, ErrorCode: LocalCode(1)}},
			{Reject: &Reject{InvokeID: &id, Problem: Problem{General: internalGeneralProblem()}}},
		}
		for i, c := range cases {
			t.Run(idNames[i]+"/"+strconv.FormatInt(id, 10), func(t *testing.T) { internalConstraint(t, internalBegin(c)) })
		}
	}
	tidNames := []string{"nil", "empty", "five-octets"}
	messageNames := []string{"Begin.OTID", "Continue.OTID", "Continue.DTID", "End.DTID", "Abort.DTID"}
	for i, tid := range []TransactionID{nil, {}, {1, 2, 3, 4, 5}} {
		for j, m := range []Message{&Begin{OTID: tid}, &Continue{OTID: tid, DTID: TransactionID{1}}, &Continue{OTID: TransactionID{1}, DTID: tid}, &End{DTID: tid}, &Abort{DTID: tid}} {
			t.Run(messageNames[j]+"/"+tidNames[i], func(t *testing.T) { internalConstraint(t, m) })
		}
	}
	componentNames := []string{"Begin.Components", "Continue.Components", "End.Components", "Unidirectional.Components"}
	for i, m := range []Message{&Begin{OTID: TransactionID{1}, Components: []Component{}}, &Continue{OTID: TransactionID{1}, DTID: TransactionID{1}, Components: []Component{}}, &End{DTID: TransactionID{1}, Components: []Component{}}, &Unidirectional{Components: []Component{}}} {
		t.Run(componentNames[i], func(t *testing.T) { internalConstraint(t, m) })
	}
	for _, value := range []int64{-1, 128} {
		cause := wire.NewPAbortCauseInt64(value)
		t.Run("Abort.PAbortCause/"+strconv.FormatInt(value, 10), func(t *testing.T) { internalConstraint(t, &Abort{DTID: TransactionID{1}, PAbortCause: &cause}) })
	}
	if _, err := (&Unidirectional{}).Marshal(); err == nil {
		t.Fatal("missing required components accepted")
	}
}

func internalConstraint(t *testing.T, m Message) {
	t.Helper()
	_, err := m.Marshal()
	var ce *ber.ValidationError
	if !errors.As(err, &ce) {
		t.Fatalf("got %v, want ValidationError", err)
	}
}

func TestInternalOID(t *testing.T) {
	for _, s := range []string{"0.0", "1.39", "2.18446744073709551535", "1.2.18446744073709551615"} {
		t.Run(s, func(t *testing.T) {
			o, err := ParseOID(s)
			if err != nil {
				t.Fatal(err)
			}
			arcs, err := o.Arcs()
			if err != nil {
				t.Fatal(err)
			}
			back, err := OIDFromArcs(arcs...)
			if err != nil || string(back) != s {
				t.Fatalf("%s %v", back, err)
			}
		})
	}
	for _, s := range []string{"", "1", "1.", ".1.2", "1..2", "1.02", "01.2", "+1.2", "1.-2", "1.2 ", " 1.2", "1.٢", "3.0", "0.40", "1.40"} {
		if _, err := ParseOID(s); !errors.Is(err, ErrInvalidOID) {
			t.Fatalf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"2.18446744073709551536", "1.2.18446744073709551616"} {
		if got, err := ParseOID(s); err != nil || string(got) != s {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if got, err := OIDFromArcs(2, math.MaxUint64); err != nil || got != "2.18446744073709551615" {
		t.Fatal(err)
	}
	for _, arcs := range [][]uint64{nil, {1}, {3, 0}, {1, 40}} {
		if _, err := OIDFromArcs(arcs...); !errors.Is(err, ErrInvalidOID) {
			t.Fatal(err)
		}
	}
}

func TestInternalCodePointers(t *testing.T) {
	local, global := LocalCode(7), GlobalCode("1.2")
	for _, code := range []Code{&local, &global} {
		if _, err := internalBegin(Component{Invoke: &Invoke{OpCode: code}}).Marshal(); err != nil {
			t.Fatal(err)
		}
	}
	for _, code := range []Code{(*LocalCode)(nil), (*GlobalCode)(nil)} {
		if _, err := internalBegin(Component{Invoke: &Invoke{OpCode: code}}).Marshal(); !errors.Is(err, ErrCodeNoAlternative) {
			t.Fatal(err)
		}
	}
}

func TestInternalParameterEndOfContents(t *testing.T) {
	for _, c := range []Component{
		{Invoke: &Invoke{OpCode: LocalCode(1), Parameter: []byte{0, 0}}},
		{ReturnError: &ReturnError{ErrorCode: LocalCode(1), Parameter: []byte{0, 0}}},
		{ReturnResultLast: &ReturnResult{Result: &Result{OpCode: LocalCode(1), Parameter: []byte{0, 0}}}},
	} {
		if _, err := internalBegin(c).Marshal(); !errors.Is(err, ber.ErrInvalidTag) {
			t.Fatalf("EOC accepted as a value: %v", err)
		}
	}
}
