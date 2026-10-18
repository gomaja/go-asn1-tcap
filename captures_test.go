package tcap_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"

	tcap "github.com/gomaja/go-asn1-tcap"
)

type captureVector struct {
	Name        string `json:"name"`
	MessageType string `json:"messageType"`
	Hex         string `json:"hex"`
}

// capV2Indefinite is the only capture whose component portion uses the
// indefinite length form (6c 80 ... 00 00).
const capV2Indefinite = "Camel-V2 invoke initialDP (CapGsmssfToGsmscfContext)"

func loadCaptures(t testing.TB) []captureVector {
	t.Helper()
	data, err := os.ReadFile("testdata/captures.json")
	if err != nil {
		t.Fatalf("read captures: %v", err)
	}
	var vectors []captureVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("decode captures: %v", err)
	}
	return vectors
}

func captureHex(t testing.TB, name string) string {
	t.Helper()
	for _, c := range loadCaptures(t) {
		if c.Name == name {
			return c.Hex
		}
	}
	t.Fatalf("capture %q not found", name)
	return ""
}

func messageTypeOf(msg tcap.Message) tcap.MessageType {
	switch msg.(type) {
	case *tcap.Begin:
		return tcap.MessageTypeBegin
	case *tcap.Continue:
		return tcap.MessageTypeContinue
	case *tcap.End:
		return tcap.MessageTypeEnd
	case *tcap.Abort:
		return tcap.MessageTypeAbort
	case *tcap.Unidirectional:
		return tcap.MessageTypeUnidirectional
	}
	return ""
}

func TestCaptures(t *testing.T) {
	captures := loadCaptures(t)
	if len(captures) != 20 {
		t.Errorf("captures.json has %d vectors, want 20", len(captures))
	}
	for _, c := range captures {
		t.Run(c.Name, func(t *testing.T) {
			msg, err := tcap.Parse(hx(c.Hex))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := messageTypeOf(msg); string(got) != c.MessageType {
				t.Fatalf("message type %q, want %q", got, c.MessageType)
			}
			out, err := msg.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if c.Name == capV2Indefinite {
				if indef, err := hasIndefiniteLength(out); err != nil || indef {
					t.Errorf("Marshal output %x: indefinite=%v err=%v", out, indef, err)
				}
				again, err := tcap.Parse(out)
				if err != nil {
					t.Fatalf("Parse(Marshal): %v", err)
				}
				assertSameMessage(t, msg, again)
				return
			}
			want := c.Hex
			if expected, ok := captureMarshalEncodings[c.Name]; ok {
				want = expected
			}
			if hex.EncodeToString(out) != want {
				t.Errorf("Marshal:\n got %x\nwant %s", out, want)
			}
		})
	}
}

func parseCapture(t *testing.T, name string) tcap.Message {
	t.Helper()
	msg, err := tcap.Parse(hx(captureHex(t, name)))
	if err != nil {
		t.Fatalf("Parse %s: %v", name, err)
	}
	return msg
}

func wantInvoke(t *testing.T, c tcap.Component, id int64, op tcap.Code, param string) {
	t.Helper()
	want := map[string]any{"type": "invoke", "invokeId": id, "linkedId": nil, "opcode": normCode(op), "parameter_hex": param}
	if got := normComponent(c); !reflect.DeepEqual(canonicalJSON(t, got), canonicalJSON(t, want)) {
		t.Errorf("component:\n got %s\nwant %s", jsonText(got), jsonText(want))
	}
}

func wantBits(t *testing.T, name string, got *runtime.BitString, bytes string, bitLength int) {
	t.Helper()
	if got == nil || hex.EncodeToString(got.Bytes) != bytes || got.BitLength != bitLength {
		t.Errorf("%s = %+v, want bytes %s bit length %d", name, got, bytes, bitLength)
	}
}

// The expected values below were read from the capture octets with the
// tags of ITU-T Q.773 (06/97) Tables 8 to 62.
func TestCaptureFields(t *testing.T) {
	t.Run("Begin SRI SM", func(t *testing.T) {
		// 62 49 | 48 04 004734a8 | 6b 1e 28 1c 06 07 00118605010101 a0 11
		// 60 0f 80 02 0780 a1 09 06 07 04000001001403 | 6c 21 a1 1f 02 01 00
		// 02 01 2d 30 17 ...
		b, ok := parseCapture(t, "Begin SRI SM").(*tcap.Begin)
		if !ok {
			t.Fatal("not a Begin")
		}
		if b.OTID.String() != "004734a8" {
			t.Errorf("OTID %s", b.OTID)
		}
		if b.Dialogue == nil || b.Dialogue.Request == nil {
			t.Fatalf("dialogue %s, want AARQ", jsonText(normDialogue(b.Dialogue)))
		}
		r := b.Dialogue.Request
		wantBits(t, "protocol-version", r.ProtocolVersion, "80", 1)
		if r.ApplicationContextName != "0.4.0.0.1.0.20.3" {
			t.Errorf("ACN %s", r.ApplicationContextName)
		}
		if r.UserInformation != nil {
			t.Errorf("user information %v, want nil", r.UserInformation)
		}
		if len(b.Components) != 1 {
			t.Fatalf("%d components", len(b.Components))
		}
		wantInvoke(t, b.Components[0], 0, tcap.LocalCode(45),
			"3017800891328490507608f38101ff820891328490000005f7")
	})

	t.Run("Begin invoke sendRoutingInfo", func(t *testing.T) {
		// AARQ without protocol-version (60 0b a1 09 ...), ACN 04 00 00 01 00 05 03,
		// invoke ID 02 01 c5 = -59, operation code 02 01 16 = 22.
		b, ok := parseCapture(t, "Begin invoke sendRoutingInfo").(*tcap.Begin)
		if !ok {
			t.Fatal("not a Begin")
		}
		if b.OTID.String() != "03ed2d12" {
			t.Errorf("OTID %s", b.OTID)
		}
		if b.Dialogue == nil || b.Dialogue.Request == nil {
			t.Fatalf("dialogue %s, want AARQ", jsonText(normDialogue(b.Dialogue)))
		}
		if b.Dialogue.Request.ProtocolVersion != nil {
			t.Errorf("protocol-version %+v, want nil", b.Dialogue.Request.ProtocolVersion)
		}
		if !tcap.OffersVersion1(b.Dialogue.Request.ProtocolVersion) {
			t.Error("absent protocol-version does not offer version1")
		}
		if b.Dialogue.Request.ApplicationContextName != "0.4.0.0.1.0.5.3" {
			t.Errorf("ACN %s", b.Dialogue.Request.ApplicationContextName)
		}
		if len(b.Components) != 1 {
			t.Fatalf("%d components", len(b.Components))
		}
		wantInvoke(t, b.Components[0], -59, tcap.LocalCode(22),
			"302b80049152828883010086079152629610103287050583370000aa0a0a0104040504038090a3ab04030205e0")
	})

	t.Run("End SRI SM response", func(t *testing.T) {
		// 49 04 02b0d1c6 | AARE 61 1b: 80 02 0780, ACN ...14 02, a2 03 02 01 00,
		// a3 05 a1 03 02 01 00 | a2 1f 02 01 00 30 1a 02 01 2d 30 15 ...
		e, ok := parseCapture(t, "End SRI SM response").(*tcap.End)
		if !ok {
			t.Fatal("not an End")
		}
		if e.DTID.String() != "02b0d1c6" {
			t.Errorf("DTID %s", e.DTID)
		}
		if e.Dialogue == nil || e.Dialogue.Response == nil {
			t.Fatalf("dialogue %s, want AARE", jsonText(normDialogue(e.Dialogue)))
		}
		r := e.Dialogue.Response
		wantBits(t, "protocol-version", r.ProtocolVersion, "80", 1)
		if r.ApplicationContextName != "0.4.0.0.1.0.20.2" {
			t.Errorf("ACN %s", r.ApplicationContextName)
		}
		if v, ok := r.Result.AsInt64(); !ok || v != 0 {
			t.Errorf("result %v, want accepted (0)", r.Result.BigInt())
		}
		d := r.ResultSourceDiagnostic
		if d.DialogueServiceUser == nil || d.DialogueServiceProvider != nil {
			t.Fatalf("diagnostic %s, want dialogue-service-user", jsonText(normDiagnostic(d)))
		}
		if v, ok := d.DialogueServiceUser.AsInt64(); !ok || v != 0 {
			t.Errorf("diagnostic %v, want null (0)", d.DialogueServiceUser.BigInt())
		}
		if len(e.Components) != 1 || e.Components[0].ReturnResultLast == nil {
			t.Fatalf("components %s", jsonText(normComponents(e.Components)))
		}
		rr := e.Components[0].ReturnResultLast
		if rr.InvokeID != 0 || rr.Result == nil {
			t.Fatalf("return result %s", jsonText(normComponent(e.Components[0])))
		}
		if rr.Result.OpCode != tcap.LocalCode(45) {
			t.Errorf("operation code %v", rr.Result.OpCode)
		}
		if got := hex.EncodeToString(rr.Result.Parameter); got != "3015040806031128951337f4a009810791126316002012" {
			t.Errorf("result parameter %s", got)
		}
	})

	t.Run("Abort DTID version mismatch", func(t *testing.T) {
		// AARE: result a2 03 02 01 01 (reject-permanent), a3 05 a1 03 02 01 02
		// (dialogue-service-user application-context-name-not-supported).
		a, ok := parseCapture(t, "Abort DTID version mismatch").(*tcap.Abort)
		if !ok {
			t.Fatal("not an Abort")
		}
		if a.DTID.String() != "02b0d1c4" {
			t.Errorf("DTID %s", a.DTID)
		}
		if a.PAbortCause != nil {
			t.Errorf("P-Abort cause %v", *a.PAbortCause)
		}
		if a.Dialogue == nil || a.Dialogue.Response == nil {
			t.Fatalf("dialogue %s, want AARE", jsonText(normDialogue(a.Dialogue)))
		}
		r := a.Dialogue.Response
		if r.ApplicationContextName != "0.4.0.0.1.0.20.2" {
			t.Errorf("ACN %s", r.ApplicationContextName)
		}
		if v, ok := r.Result.AsInt64(); !ok || v != 1 {
			t.Errorf("result %v, want reject-permanent (1)", r.Result.BigInt())
		}
		d := r.ResultSourceDiagnostic
		if d.DialogueServiceUser == nil || d.DialogueServiceProvider != nil {
			t.Fatalf("diagnostic %s", jsonText(normDiagnostic(d)))
		}
		if v, ok := d.DialogueServiceUser.AsInt64(); !ok || v != 2 {
			t.Errorf("diagnostic %v, want application-context-name-not-supported (2)", d.DialogueServiceUser.BigInt())
		}
	})

	t.Run("Abort DTID for invoke mt-forwardSM", func(t *testing.T) {
		// ABRT 64 16: 80 01 00 (dialogue-service-user), be 11 28 0f
		// 06 07 04000001010101 a0 04 a4028000.
		a, ok := parseCapture(t, "Abort DTID for invoke mt-forwardSM").(*tcap.Abort)
		if !ok {
			t.Fatal("not an Abort")
		}
		if a.DTID.String() != "03c93f57" {
			t.Errorf("DTID %s", a.DTID)
		}
		if a.Dialogue == nil || a.Dialogue.Abort == nil {
			t.Fatalf("dialogue %s, want ABRT", jsonText(normDialogue(a.Dialogue)))
		}
		if v, ok := a.Dialogue.Abort.AbortSource.AsInt64(); !ok || v != 0 {
			t.Errorf("abort source %v, want dialogue-service-user (0)", a.Dialogue.Abort.AbortSource.BigInt())
		}
		ui := a.Dialogue.Abort.UserInformation
		if len(ui) != 1 {
			t.Fatalf("user information %s", jsonText(normUserInformation(ui)))
		}
		e := ui[0]
		if e.DirectReference != "0.4.0.0.1.1.1.1" || e.IndirectReference != nil || e.DataValueDescriptor != nil ||
			e.Encoding != runtime.ExternalSingleASN1Type || hex.EncodeToString(e.SingleASN1Type) != "a4028000" {
			t.Errorf("user information %s", jsonText(normExternal(e)))
		}
	})

	t.Run("End two components", func(t *testing.T) {
		// a2 20 02 01 00 30 1b 02 01 2d 30 16 ... | a1 0c 02 01 01 02 01 3f 30 04 03 02 02 40
		e, ok := parseCapture(t, "End two components").(*tcap.End)
		if !ok {
			t.Fatal("not an End")
		}
		if e.DTID.String() != "0086e897" || len(e.Components) != 2 {
			t.Fatalf("DTID %s, %d components", e.DTID, len(e.Components))
		}
		rr := e.Components[0].ReturnResultLast
		if rr == nil || rr.InvokeID != 0 || rr.Result == nil || rr.Result.OpCode != tcap.LocalCode(45) ||
			hex.EncodeToString(rr.Result.Parameter) != "3016040826611042173454f2a00a810891328490000005f2" {
			t.Errorf("first component %s", jsonText(normComponent(e.Components[0])))
		}
		wantInvoke(t, e.Components[1], 1, tcap.LocalCode(63), "300403020240")
	})

	t.Run("Continue otid dtid long message", func(t *testing.T) {
		// No component portion: Components is nil (contract 4.3).
		c, ok := parseCapture(t, "Continue otid dtid long message").(*tcap.Continue)
		if !ok {
			t.Fatal("not a Continue")
		}
		if c.OTID.String() != "0419000f" || c.DTID.String() != "008bd040" {
			t.Errorf("OTID %s DTID %s", c.OTID, c.DTID)
		}
		if c.Components != nil {
			t.Errorf("Components %v, want nil", c.Components)
		}
		if c.Dialogue == nil || c.Dialogue.Response == nil || c.Dialogue.Response.ProtocolVersion != nil ||
			c.Dialogue.Response.ApplicationContextName != "0.4.0.0.1.0.25.3" {
			t.Errorf("dialogue %s", jsonText(normDialogue(c.Dialogue)))
		}
	})

	t.Run(capV2Indefinite, func(t *testing.T) {
		// ACN 06 07 04 00 00 01 00 32 01 = 0.4.0.0.1.0.50.1; invoke 02 01 00,
		// operation code 02 01 00 (initialDP); the argument is 30 75 ...
		b, ok := parseCapture(t, capV2Indefinite).(*tcap.Begin)
		if !ok {
			t.Fatal("not a Begin")
		}
		if b.OTID.String() != "b70801a1" {
			t.Errorf("OTID %s", b.OTID)
		}
		if b.Dialogue == nil || b.Dialogue.Request == nil || b.Dialogue.Request.ApplicationContextName != "0.4.0.0.1.0.50.1" {
			t.Fatalf("dialogue %s", jsonText(normDialogue(b.Dialogue)))
		}
		if len(b.Components) != 1 {
			t.Fatalf("%d components", len(b.Components))
		}
		wantInvoke(t, b.Components[0], 0, tcap.LocalCode(0),
			"307580010183070313890027821785010a8a088493975617699909bb0580038090a39c01029f320852507017322911f7bf34170201008107919756176999f9a309800752f099d05b37d0bf35038301119f3605f943d000039f3707919756176999f99f3807819830535304f99f39080242012280608002")
	})
}
