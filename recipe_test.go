package tcap_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// TestRecipeEncodings places each recipe in a message with the transaction
// IDs of a corpus vector. The field values are those of ITU-T Q.774
// (06/97) clauses 3.2.1, 3.2.2.1 and 3.2.3.
func TestRecipeEncodings(t *testing.T) {
	acnNotSupported := tcap.ResultSourceDiagnostic{
		DialogueServiceUser: ptr(wire.AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedValue()),
	}
	noCommonDialoguePortion := tcap.ResultSourceDiagnostic{
		DialogueServiceProvider: ptr(wire.AssociateSourceDiagnosticDialogueServiceProviderValueNoCommonDialoguePortionValue()),
	}
	cases := []struct {
		name string
		msg  tcap.Message
		want string
	}{
		// AARE 61 1b: ACN 0.4.0.0.1.0.20.2, result 1,
		// dialogue-service-user 2, explicit protocol-version {version1}.
		{"reject, application context name not supported", &tcap.Abort{DTID: tidD, Dialogue: tcap.NewRejectDialogue("0.4.0.0.1.0.20.2", acnNotSupported, nil)},
			corpusHex(t, "abort-aare-map-version-fallback")},
		// Q.774 clause 3.2.3: the received ACN, dialogue-service-provider
		// no-common-dialogue-portion (a3 05 a2 03 02 01 02), no user information.
		{"reject, no common dialogue portion", &tcap.Abort{DTID: tidD, Dialogue: tcap.NewRejectDialogue(acn3, noCommonDialoguePortion, nil)},
			corpusHex(t, "abort-aare-provider-no-common-dialogue")},
		// ABRT 64 03 80 01 01.
		{"provider abort", &tcap.Abort{DTID: tidD, Dialogue: tcap.NewProviderAbortDialogue()},
			corpusHex(t, "abort-abrt-provider")},
		// ABRT 64 16 80 01 00 be 11 ...
		{"user abort with MAP user information", &tcap.Abort{DTID: tidD, Dialogue: tcap.NewUserAbortDialogue([]tcap.External{mapUserAbortExt()})},
			corpusHex(t, "abort-abrt-user-map-userabort")},
		{"user abort without user information", &tcap.Abort{DTID: tidD, Dialogue: tcap.NewUserAbortDialogue(nil)},
			tlv("67", hexDTID, dialoguePortion(hexDialogueAS, hexABRTUser))},
		// AARE 61 1b with result 0 and dialogue-service-user null.
		{"accept in the first backward Continue", &tcap.Continue{OTID: tidO, DTID: tidD, Dialogue: tcap.NewAcceptDialogue(acn3, nil), Components: []tcap.Component{
			{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(45), Parameter: hx("30040402aabb")}}},
		}}, corpusHex(t, "continue-first-backward-aare-result")},
		{"accept in an End", &tcap.End{DTID: tidD, Dialogue: tcap.NewAcceptDialogue(acn3, nil)},
			tlv("64", hexDTID, dialoguePortion(hexDialogueAS, hexAAREAcc))},
		{"accept with user information", &tcap.End{DTID: tidD, Dialogue: tcap.NewAcceptDialogue(acn3, []tcap.External{mapUserAbortExt()})},
			tlv("64", hexDTID, dialoguePortion(hexDialogueAS, tlv("61", hexPV1, hexACN3, "a203020100", "a305a103020100", tlv("be", "280f060704000001010101a004a4028000"))))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := c.msg.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if got := hex.EncodeToString(out); got != c.want {
				t.Errorf("Marshal:\n got %s\nwant %s", got, c.want)
			}
		})
	}
}

// TestRecipeFields checks the recipes field by field (contract section 5).
func TestRecipeFields(t *testing.T) {
	isVersion1 := func(t *testing.T, v *runtime.BitString) {
		t.Helper()
		wantBits(t, "protocol-version", v, "80", 1)
	}
	t.Run("NewAcceptDialogue", func(t *testing.T) {
		d := tcap.NewAcceptDialogue("0.4.0.0.1.0.25.3", nil)
		if d == nil || d.Response == nil || d.Request != nil || d.Abort != nil || d.Unidirectional != nil || d.Opaque != nil {
			t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
		}
		r := d.Response
		isVersion1(t, r.ProtocolVersion)
		if r.ApplicationContextName != "0.4.0.0.1.0.25.3" {
			t.Errorf("ACN %s", r.ApplicationContextName)
		}
		if v, ok := r.Result.AsInt64(); !ok || v != 0 {
			t.Errorf("result %v, want accepted", r.Result.BigInt())
		}
		if r.ResultSourceDiagnostic.DialogueServiceProvider != nil || r.ResultSourceDiagnostic.DialogueServiceUser == nil {
			t.Fatalf("diagnostic %s", jsonText(normDiagnostic(r.ResultSourceDiagnostic)))
		}
		if v, ok := r.ResultSourceDiagnostic.DialogueServiceUser.AsInt64(); !ok || v != 0 {
			t.Errorf("diagnostic %v, want null", r.ResultSourceDiagnostic.DialogueServiceUser.BigInt())
		}
		if r.UserInformation != nil {
			t.Errorf("user information %v, want nil", r.UserInformation)
		}
	})
	t.Run("NewRejectDialogue", func(t *testing.T) {
		diag := tcap.ResultSourceDiagnostic{DialogueServiceUser: ptr(wire.AssociateSourceDiagnosticDialogueServiceUserValueNoReasonGivenValue())}
		ui := []tcap.External{mapUserAbortExt()}
		d := tcap.NewRejectDialogue(acn3, diag, ui)
		if d == nil || d.Response == nil || d.Request != nil || d.Abort != nil || d.Unidirectional != nil || d.Opaque != nil {
			t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
		}
		r := d.Response
		isVersion1(t, r.ProtocolVersion)
		if v, ok := r.Result.AsInt64(); !ok || v != 1 {
			t.Errorf("result %v, want reject-permanent", r.Result.BigInt())
		}
		want := map[string]any{"kind": "user", "value": int64(1)}
		if got := normDiagnostic(r.ResultSourceDiagnostic); !reflect.DeepEqual(canonicalJSON(t, got), canonicalJSON(t, want)) {
			t.Errorf("diagnostic %s", jsonText(got))
		}
		if got := jsonText(normUserInformation(r.UserInformation)); got != jsonText(normUserInformation(ui)) {
			t.Errorf("user information %s", got)
		}
	})
	t.Run("NewUserAbortDialogue", func(t *testing.T) {
		d := tcap.NewUserAbortDialogue(nil)
		if d == nil || d.Abort == nil || d.Request != nil || d.Response != nil || d.Unidirectional != nil || d.Opaque != nil {
			t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
		}
		if v, ok := d.Abort.AbortSource.AsInt64(); !ok || v != 0 {
			t.Errorf("abort source %v, want dialogue-service-user", d.Abort.AbortSource.BigInt())
		}
		if d.Abort.UserInformation != nil {
			t.Errorf("user information %v, want nil", d.Abort.UserInformation)
		}
	})
	t.Run("NewProviderAbortDialogue", func(t *testing.T) {
		d := tcap.NewProviderAbortDialogue()
		if d == nil || d.Abort == nil || d.Request != nil || d.Response != nil || d.Unidirectional != nil || d.Opaque != nil {
			t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
		}
		if v, ok := d.Abort.AbortSource.AsInt64(); !ok || v != 1 {
			t.Errorf("abort source %v, want dialogue-service-provider", d.Abort.AbortSource.BigInt())
		}
		if d.Abort.UserInformation != nil {
			t.Errorf("user information %v, want nil", d.Abort.UserInformation)
		}
	})
	// The accepted AARE of corpus end-aare-single-response differs from the
	// recipe only in leaving out protocol-version.
	t.Run("end-aare-single-response", func(t *testing.T) {
		d := messageDialogue(mustParse(t, corpusHex(t, "end-aare-single-response")))
		recipe := tcap.NewAcceptDialogue(acn3, nil)
		if d == nil || d.Response == nil || d.Response.ProtocolVersion != nil {
			t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
		}
		d.Response.ProtocolVersion = tcap.ProtocolVersion1()
		if got, want := jsonText(normDialogue(d)), jsonText(normDialogue(recipe)); got != want {
			t.Errorf("dialogue:\n got %s\nwant %s", got, want)
		}
	})
}

// TestRecipesCopySlices: "Recipes copy their slice arguments" (contract
// section 5).
func TestRecipesCopySlices(t *testing.T) {
	other := tcap.External{DirectReference: "1.2.3", Encoding: runtime.ExternalOctetAligned, OctetAligned: hx("ff")}
	diag := tcap.ResultSourceDiagnostic{DialogueServiceUser: userNull()}
	recipes := []struct {
		name string
		make func(ui []tcap.External) []tcap.External
	}{
		{"NewAcceptDialogue", func(ui []tcap.External) []tcap.External {
			return tcap.NewAcceptDialogue(acn3, ui).Response.UserInformation
		}},
		{"NewRejectDialogue", func(ui []tcap.External) []tcap.External {
			return tcap.NewRejectDialogue(acn3, diag, ui).Response.UserInformation
		}},
		{"NewUserAbortDialogue", func(ui []tcap.External) []tcap.External { return tcap.NewUserAbortDialogue(ui).Abort.UserInformation }},
	}
	for _, r := range recipes {
		t.Run(r.name, func(t *testing.T) {
			ui := []tcap.External{mapUserAbortExt(), mapUserAbortExt()}
			got := r.make(ui)
			want := jsonText(normUserInformation([]tcap.External{mapUserAbortExt(), mapUserAbortExt()}))
			ui[0] = other
			ui[1] = other
			if jsonText(normUserInformation(got)) != want {
				t.Errorf("user information follows the argument: %s", jsonText(normUserInformation(got)))
			}
		})
	}
}

func TestProtocolVersion1(t *testing.T) {
	a := tcap.ProtocolVersion1()
	wantBits(t, "ProtocolVersion1()", a, "80", 1)
	b := tcap.ProtocolVersion1()
	if a == b {
		t.Fatal("ProtocolVersion1 returned the same pointer twice")
	}
	a.Bytes[0] = 0x40
	a.BitLength = 2
	wantBits(t, "ProtocolVersion1() after changing an earlier result", b, "80", 1)
	wantBits(t, "a third ProtocolVersion1()", tcap.ProtocolVersion1(), "80", 1)
	if !tcap.OffersVersion1(tcap.ProtocolVersion1()) {
		t.Error("OffersVersion1(ProtocolVersion1()) = false")
	}
}

// TestOffersVersion1: absent means DEFAULT {version1} (Q.773 clause 3.2.1);
// otherwise bit 0, version1, must be set (contract section 5).
func TestOffersVersion1(t *testing.T) {
	cases := []struct {
		name string
		pv   *runtime.BitString
		want bool
	}{
		{"absent", nil, true},
		{"version1", pv("80", 1), true},
		{"version1 and bit 1", pv("c0", 2), true},
		{"version1 with trailing zero bits", pv("80", 8), true},
		{"version1 in a longer string", pv("8001", 16), true},
		{"only bit 1", pv("40", 2), false},
		{"bit 0 clear", pv("00", 1), false},
		{"empty", &runtime.BitString{}, false},
		{"empty with a stray octet", &runtime.BitString{Bytes: hx("80"), BitLength: 0}, false},
	}
	for _, c := range cases {
		if got := tcap.OffersVersion1(c.pv); got != c.want {
			t.Errorf("%s: OffersVersion1 = %v, want %v", c.name, got, c.want)
		}
	}
}
