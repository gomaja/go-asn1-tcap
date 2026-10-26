package tcap_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
)

func TestPublicAbortValues(t *testing.T) {
	diagnostic := tcap.NewDialogueServiceUserDiagnostic(tcap.DialogueServiceUserApplicationContextNameNotSupported)
	cause := tcap.NewPAbortCause(tcap.PAbortCauseUnrecognizedTransactionID)
	for _, tt := range []struct {
		name    string
		message *tcap.Abort
		wireHex string
	}{
		{
			name: "refusal",
			message: &tcap.Abort{
				DTID: tcap.TransactionID{0, 0, 0, 1},
				Dialogue: tcap.NewRejectDialogue("0.4.0.0.1.0.25.2",
					tcap.ResultSourceDiagnostic{DialogueServiceUser: &diagnostic}, nil),
			},
			wireHex: "67324904000000016b2a2828060700118605010101a01d611b80020780a109060704000001001902a203020101a305a103020102",
		},
		{
			name:    "P-Abort",
			message: &tcap.Abort{DTID: tcap.TransactionID{0, 0, 0, 1}, PAbortCause: &cause},
			wireHex: "67094904000000014a0101",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.message.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(encoded); got != tt.wireHex {
				t.Fatalf("Marshal = %s; want %s", got, tt.wireHex)
			}
			parsed, err := tcap.Parse(encoded)
			if err != nil {
				t.Fatal(err)
			}
			abort, ok := parsed.(*tcap.Abort)
			if !ok {
				t.Fatalf("Parse returned %T; want *tcap.Abort", parsed)
			}
			if !bytes.Equal(abort.DTID, tt.message.DTID) {
				t.Fatalf("DTID = %x; want %x", abort.DTID, tt.message.DTID)
			}
			if tt.message.PAbortCause != nil {
				if abort.PAbortCause == nil {
					t.Fatal("missing P-Abort cause")
				}
				if v, ok := abort.PAbortCause.AsInt64(); !ok || v != tcap.PAbortCauseUnrecognizedTransactionID {
					t.Fatalf("P-Abort cause = %v; want unrecognizedTransactionID", abort.PAbortCause)
				}
				return
			}
			if abort.Dialogue == nil || abort.Dialogue.Response == nil {
				t.Fatal("missing refusal AARE")
			}
			aare := abort.Dialogue.Response
			if v, ok := aare.Result.AsInt64(); !ok || v != tcap.AssociateResultRejectPermanent {
				t.Fatalf("result = %v; want reject-permanent", aare.Result)
			}
			if aare.ApplicationContextName != "0.4.0.0.1.0.25.2" {
				t.Fatalf("application context = %s", aare.ApplicationContextName)
			}
			user := aare.ResultSourceDiagnostic.DialogueServiceUser
			if user == nil {
				t.Fatal("missing dialogue-service-user diagnostic")
			}
			if v, ok := user.AsInt64(); !ok || v != tcap.DialogueServiceUserApplicationContextNameNotSupported {
				t.Fatalf("diagnostic = %v; want application-context-name-not-supported", user)
			}
		})
	}
}

func TestPublicProblemAlternatives(t *testing.T) {
	general := tcap.NewGeneralProblem(tcap.GeneralProblemUnrecognizedPDU)
	invoke := tcap.NewInvokeProblem(tcap.InvokeProblemUnrecognizedOperation)
	result := tcap.NewReturnResultProblem(tcap.ReturnResultProblemMistypedResult)
	returnError := tcap.NewReturnErrorProblem(tcap.ReturnErrorProblemUnrecognizedError)
	for _, tt := range []struct {
		name    string
		problem tcap.Problem
	}{
		{"general", tcap.Problem{General: &general}},
		{"invoke", tcap.Problem{Invoke: &invoke}},
		{"return-result", tcap.Problem{ReturnResult: &result}},
		{"return-error", tcap.Problem{ReturnError: &returnError}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := &tcap.End{DTID: tcap.TransactionID{1}, Components: []tcap.Component{{Reject: &tcap.Reject{Problem: tt.problem}}}}
			checkPublicRoundTrip(t, message)
		})
	}
}

func TestPublicExternalEncodings(t *testing.T) {
	for _, tt := range []struct {
		name     string
		external tcap.External
	}{
		{"single-ASN1-type", tcap.External{DirectReference: "1.2.3", Encoding: tcap.ExternalSingleASN1Type, SingleASN1Type: []byte{0x05, 0x00}}},
		{"octet-aligned", tcap.External{DirectReference: "1.2.3", Encoding: tcap.ExternalOctetAligned, OctetAligned: []byte{1, 2, 3}}},
		{"arbitrary", tcap.External{DirectReference: "1.2.3", Encoding: tcap.ExternalArbitrary, Arbitrary: tcap.BitString{Bytes: []byte{0x80}, BitLength: 1}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := &tcap.Begin{
				OTID: tcap.TransactionID{1},
				Dialogue: &tcap.Dialogue{Request: &tcap.AARQ{
					ProtocolVersion:        &tcap.BitString{Bytes: []byte{0x80}, BitLength: 1},
					ApplicationContextName: "0.4.0.0.1.0.25.2",
					UserInformation:        []tcap.External{tt.external},
				}},
			}
			checkPublicRoundTrip(t, message)
		})
	}
}

func checkPublicRoundTrip(t *testing.T, message tcap.Message) {
	t.Helper()
	encoded, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tcap.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, message) {
		t.Fatalf("Parse changed the message: got %#v; want %#v", parsed, message)
	}
	reencoded, err := parsed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("Marshal after Parse = %x; want %x", reencoded, encoded)
	}
}
