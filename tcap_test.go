package tcap

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1-tcap/gsmmap"
)

// Test data from real TCAP captures (same as go-tcap test suite).
func TestParse_RealCaptures(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		msgType     MessageType
		expectError bool
	}{
		{
			name:    "Begin SRI SM",
			input:   "62494804004734a86b1e281c060700118605010101a011600f80020780a1090607040000010014036c21a11f02010002012d3017800891328490507608f38101ff820891328490000005f7",
			msgType: MessageTypeBegin,
		},
		{
			name:    "Begin otid long message",
			input:   "62264804008bd0406b1e281c060700118605010101a011600f80020780a109060704000001001903",
			msgType: MessageTypeBegin,
		},
		{
			name:    "Begin invoke reportSM-DeliveryStatus",
			input:   "6247480403c940ec6b1e281c060700118605010101a011600f80020780a1090607040000010014036c1fa11d02010002012f30150407910201068163280407916427417901f00a0101",
			msgType: MessageTypeBegin,
		},
		{
			name:    "Begin invoke alertServiceCentre",
			input:   "6240480400d199b06b1a2818060700118605010101a00d600ba1090607040000010017026c1ca11a0201010201403012040891881088775859f70406915418730536",
			msgType: MessageTypeBegin,
		},
		{
			name:    "Begin invoke alertServiceCentreWithoutResult",
			input:   "622448047c0801f86c1ca11a02010102013130120407917933192122f30407916427417960f1",
			msgType: MessageTypeBegin,
		},
		{
			name:    "Begin invoke forwardSM",
			input:   "62818a48048c150d066c8181a17f02010002012e3077800832140080803138f684069169318488880463040b916971101174f40000422182612464805bd2e2b1252d467ff6de6c47efd96eb6a1d056cb0d69b49a10269c098537586e96931965b260d15613da72c29b91261bde72c6a1ad2623d682b5996d58331271375a0d1733eee4bd98ec768bd966b41c0d",
			msgType: MessageTypeBegin,
		},
		{
			name:    "Begin invoke sendRoutingInfo",
			input:   "6259480403ed2d126b1a2818060700118605010101a00d600ba1090607040000010005036c35a1330201c5020116302b80049152828883010086079152629610103287050583370000aa0a0a0104040504038090a3ab04030205e0",
			msgType: MessageTypeBegin,
		},
		{
			name:    "Begin invoke mt-forwardSM",
			input:   "6281b8480403c93f576b1e281c060700118605010101a011600f80020780a1090607040000010019036c818fa1818c02010002012c308183800874020110261338f38407916427417901f0046e040bd0536152e85c0200004221824143220068c1f1f85d77d341582c360693c16c322c168bc5828865719a5e2683ee693a1ad4b44a4136180ce68281de6e900cf78ac95e321a0b449587dd7373592e2f9341d4372838bd06a9c82ca8e99a2689c8a00b34152641cd309b9cb697e7",
			msgType: MessageTypeBegin,
		},
		{
			name:    "End error SRI SM",
			input:   "643d4904004734a86b262824060700118605010101a0196117a109060704000001001403a203020100a305a1030201006c0da30b02010002010130030a0100",
			msgType: MessageTypeEnd,
		},
		{
			name:    "End SRI SM response",
			input:   "6455490402b0d1c66b2a2828060700118605010101a01d611b80020780a109060704000001001402a203020100a305a1030201006c21a21f020100301a02012d3015040806031128951337f4a009810791126316002012",
			msgType: MessageTypeEnd,
		},
		{
			name:    "End returnResultLast",
			input:   "640d4904008bd0406c05a203020102",
			msgType: MessageTypeEnd,
		},
		{
			name:    "End returnResultLast response for FSM",
			input:   "64354904000000016b262824060700118605010101a0196117a109060704000001001903a203020100a305a1030201006c05a203020100",
			msgType: MessageTypeEnd,
		},
		{
			name:    "End two components",
			input:   "646049040086e8976b262824060700118605010101a0196117a109060704000001001403a203020100a305a1030201006c30a220020100301b02012d3016040826611042173454f2a00a810891328490000005f2a10c02010102013f300403020240",
			msgType: MessageTypeEnd,
		},
		{
			name:    "Continue otid dtid long message",
			input:   "653448040419000f4904008bd0406b262824060700118605010101a0196117a109060704000001001903a203020100a305a103020100",
			msgType: MessageTypeContinue,
		},
		{
			name:    "Continue invoke mt-forwardSM fragment",
			input:   "6581d24804008bd04049040419000f6c81c3a181c002010102012c3081b7800826610011829761f6840891328490000005f704819e4009d047f6dbfe06000042217251400000a00500035f020190e53c0b947fd741e8b0bd0c9abfdb6510bcec26a7dd67d09c5e86cf41693728ffaecb41f2f2393da7cbc3f4f4db0d82cbdfe3f27cee0241d9e5f0bc0c32bfd9ecf71d44479741ecb47b0da2bf41e3771bce2ed3cb203abadc0685dd64d09c1e96d341e4323b6d2fcbd3ee33888e96bfeb6734e8c87edbdf2190bc3c96d7d3f476d94d77d5e70500",
			msgType: MessageTypeContinue,
		},
		{
			name:    "Continue returnResultLast",
			input:   "651348040419000f4904008bd0406c05a203020101",
			msgType: MessageTypeContinue,
		},
		{
			name:    "Continue invoke forwardSM fragment 2",
			input:   "655a4804008bd04049040419000f6c4ca14a02010202012c3042800826610011829761f6840891328490000005f7042c4409d047f6dbfe060000422172514000001d0500035f0202cae8ba5c9e2ecb5de377fb157ea9d1b0d93b1e06",
			msgType: MessageTypeContinue,
		},
		{
			name:    "Abort DTID version mismatch",
			input:   "6732490402b0d1c46b2a2828060700118605010101a01d611b80020780a109060704000001001402a203020101a305a103020102",
			msgType: MessageTypeAbort,
		},
		{
			name:    "Abort DTID for invoke mt-forwardSM",
			input:   "672d490403c93f576b252823060700118605010101a0186416800100be11280f060704000001010101a004a4028000",
			msgType: MessageTypeAbort,
		},
		{
			name:    "Camel-V2 invoke initialDP (CapGsmssfToGsmscfContext)",
			input:   "6281a94804b70801a16b1e281c060700118605010101a011600f80020780a1090607040000010032016c80a17d020100020100307580010183070313890027821785010a8a088493975617699909bb0580038090a39c01029f320852507017322911f7bf34170201008107919756176999f9a309800752f099d05b37d0bf35038301119f3605f943d000039f3707919756176999f99f3807819830535304f99f390802420122806080020000",
			msgType: MessageTypeBegin,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tcapBytes, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatalf("failed to decode hex input: %v", err)
			}

			parsed, err := Parse(tcapBytes)
			if err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			if parsed.MessageType() != tc.msgType {
				t.Errorf("expected message type %s, got %s", tc.msgType, parsed.MessageType())
			}

			// Roundtrip: marshal back and compare bytes.
			marshalled, err := parsed.Marshal()
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			if !bytes.Equal(tcapBytes, marshalled) {
				t.Errorf("roundtrip not stable:\n  first:  %s\n  second: %s",
					hex.EncodeToString(tcapBytes), hex.EncodeToString(marshalled))
			}
		})
	}
}

func TestParse_EmptyData(t *testing.T) {
	_, err := Parse(nil)
	if err == nil {
		t.Fatal("expected error for nil data")
	}

	_, err = Parse([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestNewBegin_Validation(t *testing.T) {
	tests := []struct {
		name    string
		otid    []byte
		wantErr bool
	}{
		{name: "valid 1 byte", otid: []byte{0x01}, wantErr: false},
		{name: "valid 4 bytes", otid: []byte{0x01, 0x02, 0x03, 0x04}, wantErr: false},
		{name: "empty", otid: []byte{}, wantErr: true},
		{name: "too long", otid: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, wantErr: true},
		{name: "nil", otid: nil, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewBegin(tc.otid)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewBegin() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewEnd_Validation(t *testing.T) {
	_, err := NewEnd([]byte{})
	if err == nil {
		t.Fatal("expected error for empty dtid")
	}

	_, err = NewEnd([]byte{0x01})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewContinue_Validation(t *testing.T) {
	_, err := NewContinue([]byte{}, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for empty otid")
	}

	_, err = NewContinue([]byte{0x01}, []byte{})
	if err == nil {
		t.Fatal("expected error for empty dtid")
	}

	_, err = NewContinue([]byte{0x01}, []byte{0x02})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithBeginInvoke_Validation(t *testing.T) {
	_, err := NewBegin([]byte{0x01}, WithBeginInvoke(-129, 45, nil))
	if err == nil {
		t.Fatal("expected error for invoke ID -129")
	}

	_, err = NewBegin([]byte{0x01}, WithBeginInvoke(128, 45, nil))
	if err == nil {
		t.Fatal("expected error for invoke ID 128")
	}

	_, err = NewBegin([]byte{0x01}, WithBeginInvoke(0, 45, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewBegin_MarshalRoundtrip(t *testing.T) {
	msg, err := NewBegin([]byte{0x00, 0x47, 0x34, 0xa8},
		WithBeginDialogueRequest(20, 3),
		WithBeginInvoke(0, 45, hexDecode(t, "800891328490507608f38101ff820891328490000005f7")),
	)
	if err != nil {
		t.Fatalf("NewBegin: %v", err)
	}

	marshalled, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	parsed, err := Parse(marshalled)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.MessageType() != MessageTypeBegin {
		t.Errorf("expected Begin, got %s", parsed.MessageType())
	}

	begin, ok := parsed.(*BeginTCAP)
	if !ok {
		t.Fatal("expected *BeginTCAP")
	}

	if len(begin.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(begin.Components))
	}

	if begin.Components[0].Invoke == nil {
		t.Fatal("expected Invoke component")
	}

	if begin.Components[0].Invoke.OpCode != 45 {
		t.Errorf("expected opcode 45, got %d", begin.Components[0].Invoke.OpCode)
	}
}

func TestNewEnd_MarshalRoundtrip(t *testing.T) {
	msg, err := NewEnd([]byte{0x00, 0x8b, 0xd0, 0x40},
		WithEndReturnResultLast(2, nil, nil),
	)
	if err != nil {
		t.Fatalf("NewEnd: %v", err)
	}

	marshalled, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	parsed, err := Parse(marshalled)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.MessageType() != MessageTypeEnd {
		t.Errorf("expected End, got %s", parsed.MessageType())
	}
}

func TestNewContinue_MarshalRoundtrip(t *testing.T) {
	msg, err := NewContinue([]byte{0x04, 0x19, 0x00, 0x0f}, []byte{0x00, 0x8b, 0xd0, 0x40},
		WithContinueDialogueResponse(25, 3),
	)
	if err != nil {
		t.Fatalf("NewContinue: %v", err)
	}

	marshalled, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	parsed, err := Parse(marshalled)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.MessageType() != MessageTypeContinue {
		t.Errorf("expected Continue, got %s", parsed.MessageType())
	}
}

func TestDialogueResponseFromRequest(t *testing.T) {
	dlg := newDialogueRequest(20, 3)

	resp, err := NewDialogueResponseFromDialogueRequest(dlg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if resp.Response == nil {
		t.Fatal("expected response dialogue")
	}

	if resp.Response.ProtocolVersion == nil {
		t.Fatal("expected protocol version")
	}

	if *resp.Response.ProtocolVersion != DefaultProtocolVersion {
		t.Errorf("expected protocol version %d, got %d", DefaultProtocolVersion, *resp.Response.ProtocolVersion)
	}
}

func TestDialogueResponseFromRequest_Nil(t *testing.T) {
	resp, err := NewDialogueResponseFromDialogueRequest(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response for nil request")
	}
}

func TestNewBegin_WithSubpackageConstants(t *testing.T) {
	msg, err := NewBegin([]byte{0x00, 0x47, 0x34, 0xa8},
		WithBeginDialogueRequest(gsmmap.ShortMsgGatewayContext, gsmmap.Version3),
		WithBeginInvoke(0, gsmmap.OpCodeSendRoutingInfoForSM, hexDecode(t, "800891328490507608f38101ff820891328490000005f7")),
	)
	if err != nil {
		t.Fatalf("NewBegin: %v", err)
	}

	marshalled, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	parsed, err := Parse(marshalled)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.MessageType() != MessageTypeBegin {
		t.Errorf("expected Begin, got %s", parsed.MessageType())
	}

	begin, ok := parsed.(*BeginTCAP)
	if !ok {
		t.Fatal("expected *BeginTCAP")
	}

	if begin.Components[0].Invoke.OpCode != gsmmap.OpCodeSendRoutingInfoForSM {
		t.Errorf("expected opcode %d, got %d", gsmmap.OpCodeSendRoutingInfoForSM, begin.Components[0].Invoke.OpCode)
	}
}

func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}
