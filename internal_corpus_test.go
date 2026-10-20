package tcap

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

type internalVector struct {
	ID     string                     `json:"id"`
	Name   string                     `json:"name"`
	Valid  bool                       `json:"valid"`
	Hex    string                     `json:"hex"`
	Intent map[string]json.RawMessage `json:"intent"`
}

func internalVectors(t *testing.T, file string) []internalVector {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []internalVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func internalHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInternalCorpus(t *testing.T) {
	for _, v := range internalVectors(t, "testdata/corpus.json") {
		t.Run(v.ID, func(t *testing.T) {
			data := internalHex(t, v.Hex)
			m, err := Parse(data)
			valid := v.Valid && v.ID != "begin-linked-absent"
			if !valid {
				var pe *ParseError
				if !errors.As(err, &pe) || m != nil {
					t.Fatalf("got %T, %v", m, err)
				}
				internalNegative(t, v.ID, pe)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			internalCheckIntent(t, m, v.Intent)
			encoded, err := m.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			expected := data
			if !strings.Contains(v.ID, "indefinite") && !bytes.Equal(encoded, expected) {
				t.Fatalf("encoding %x, want %x", encoded, expected)
			}
			again, err := Parse(encoded)
			if err != nil || !reflect.DeepEqual(m, again) {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}

func internalNegative(t *testing.T, id string, pe *ParseError) {
	t.Helper()
	portion, index := PortionTransaction, -1
	var sentinel error
	constraint := false
	switch id {
	case "begin-linked-absent":
		portion, index, constraint = PortionComponent, 0, true
	case "negative-empty-components":
		portion, constraint = PortionComponent, true
	case "negative-invokeid-128", "negative-invokeid--129":
		portion, index, constraint = PortionComponent, 0, true
	case "negative-otid-0", "negative-otid-5", "negative-dtid-zero", "negative-dtid-five", "negative-p-abort-cause-128", "negative-p-abort-cause-minus-one":
		constraint = true
	case "negative-unknown-message-tag":
		sentinel = ErrUnrecognizedMessageType
	case "negative-primitive-single-asn1-type":
		portion = PortionDialogue
	case "negative-abort-aarq":
		portion, sentinel = PortionDialogue, ErrUnexpectedDialoguePDU
	}
	if pe.Portion != portion || pe.ComponentIndex != index {
		t.Fatalf("context: %+v", pe)
	}
	messageType := MessageTypeBegin
	switch {
	case id == "negative-unknown-message-tag":
		messageType = ""
	case strings.HasPrefix(id, "negative-dtid"):
		messageType = MessageTypeEnd
	case strings.Contains(id, "abort"):
		messageType = MessageTypeAbort
	case strings.Contains(id, "unidirectional"):
		messageType = MessageTypeUnidirectional
	}
	if pe.MessageType != messageType {
		t.Fatalf("message type %s, want %s", pe.MessageType, messageType)
	}
	if strings.HasPrefix(id, "negative-otid") && pe.OTID != nil {
		t.Fatalf("invalid OTID derived: %x", pe.OTID)
	}
	if strings.Contains(id, "abort") && pe.DTID.String() != "05060708" {
		t.Fatalf("DTID not derived: %x", pe.DTID)
	}
	if sentinel != nil && !errors.Is(pe, sentinel) {
		t.Fatalf("want %v, got %v", sentinel, pe)
	}
	var ce *ber.ValidationError
	if constraint && !errors.As(pe, &ce) {
		t.Fatalf("missing ValidationError: %v", pe)
	}
	if strings.Contains(id, "invokeid") && pe.InvokeID != nil {
		t.Fatalf("invalid ID derived: %d", *pe.InvokeID)
	}
	if id == "begin-linked-absent" && (pe.InvokeID == nil || *pe.InvokeID != 3 || pe.OTID.String() != "01020304") {
		t.Fatalf("context: %+v", pe)
	}
}

func internalCheckIntent(t *testing.T, m Message, intent map[string]json.RawMessage) {
	t.Helper()
	var otid, dtid TransactionID
	var components []Component
	var dialogue *Dialogue
	var name string
	switch m := m.(type) {
	case *Begin:
		name, otid, components, dialogue = "begin", m.OTID, m.Components, m.Dialogue
	case *Continue:
		name, otid, dtid, components, dialogue = "continue", m.OTID, m.DTID, m.Components, m.Dialogue
	case *End:
		name, dtid, components, dialogue = "end", m.DTID, m.Components, m.Dialogue
	case *Abort:
		name, dtid, dialogue = "abort", m.DTID, m.Dialogue
	case *Unidirectional:
		name, components, dialogue = "unidirectional", m.Components, m.Dialogue
	}
	var expected string
	if err := json.Unmarshal(intent["message_type"], &expected); err != nil || name != expected {
		t.Fatalf("type: %s, want %s (%v)", name, expected, err)
	}
	for k, id := range map[string]TransactionID{"otid": otid, "dtid": dtid} {
		if raw, ok := intent[k]; ok {
			if err := json.Unmarshal(raw, &expected); err != nil || id.String() != expected {
				t.Fatalf("%s: %x, want %s", k, id, expected)
			}
		}
	}
	var cs []struct {
		Type      string                     `json:"type"`
		InvokeID  *int64                     `json:"invokeId"`
		LinkedID  *int64                     `json:"linkedId"`
		Parameter *string                    `json:"parameter_hex"`
		OpCode    map[string]json.RawMessage `json:"opcode"`
		ErrorCode map[string]json.RawMessage `json:"errcode"`
		Result    *struct {
			OpCode    map[string]json.RawMessage `json:"opcode"`
			Parameter string                     `json:"parameter_hex"`
		} `json:"result"`
		Problem *struct {
			Kind  string `json:"kind"`
			Value int64  `json:"value"`
		} `json:"problem"`
	}
	if err := json.Unmarshal(intent["components"], &cs); err != nil {
		t.Fatal(err)
	}
	if len(cs) != len(components) {
		t.Fatalf("component count %d, want %d", len(components), len(cs))
	}
	for i, c := range components {
		var id *int64
		var parameter []byte
		var kind string
		switch {
		case c.Invoke != nil:
			kind, id, parameter = "invoke", &c.Invoke.InvokeID, c.Invoke.Parameter
		case c.ReturnResultLast != nil:
			kind, id = "returnResultLast", &c.ReturnResultLast.InvokeID
		case c.ReturnResultNotLast != nil:
			kind, id = "returnResultNotLast", &c.ReturnResultNotLast.InvokeID
		case c.ReturnError != nil:
			kind, id, parameter = "returnError", &c.ReturnError.InvokeID, c.ReturnError.Parameter
		case c.Reject != nil:
			kind, id = "reject", c.Reject.InvokeID
		}
		if kind != cs[i].Type || !reflect.DeepEqual(id, cs[i].InvokeID) {
			t.Fatalf("component %d: %+v", i, c)
		}
		if cs[i].Parameter != nil && hex.EncodeToString(parameter) != *cs[i].Parameter {
			t.Fatalf("parameter %d: %x", i, parameter)
		}
		if c.Invoke != nil {
			internalCheckCode(t, c.Invoke.OpCode, cs[i].OpCode)
			if !reflect.DeepEqual(c.Invoke.LinkedID, cs[i].LinkedID) {
				t.Fatalf("linked ID %d", i)
			}
		}
		if c.ReturnError != nil {
			internalCheckCode(t, c.ReturnError.ErrorCode, cs[i].ErrorCode)
		}
		result := c.ReturnResultLast
		if result == nil {
			result = c.ReturnResultNotLast
		}
		if result != nil {
			if (result.Result == nil) != (cs[i].Result == nil) {
				t.Fatalf("result presence %d", i)
			}
			if result.Result != nil {
				internalCheckCode(t, result.Result.OpCode, cs[i].Result.OpCode)
				if hex.EncodeToString(result.Result.Parameter) != cs[i].Result.Parameter {
					t.Fatalf("result parameter %d", i)
				}
			}
		}
		if c.Reject != nil {
			p := c.Reject.Problem
			var kind string
			var value int64
			switch {
			case p.General != nil:
				kind = "general"
				value = p.General.BigInt().Int64()
			case p.Invoke != nil:
				kind = "invoke"
				value = p.Invoke.BigInt().Int64()
			case p.ReturnResult != nil:
				kind = "returnResult"
				value = p.ReturnResult.BigInt().Int64()
			case p.ReturnError != nil:
				kind = "returnError"
				value = p.ReturnError.BigInt().Int64()
			}
			if cs[i].Problem == nil || kind != cs[i].Problem.Kind || value != cs[i].Problem.Value {
				t.Fatalf("problem %d", i)
			}
		}
	}
	if string(intent["dialogue"]) == "null" && dialogue != nil {
		t.Fatal("unexpected dialogue")
	}
	if raw := intent["dialogue"]; string(raw) != "null" {
		internalCheckDialogueIntent(t, dialogue, raw)
	}
	if abort, ok := m.(*Abort); ok {
		var cause *int64
		if err := json.Unmarshal(intent["p_abort_cause"], &cause); err != nil {
			t.Fatal(err)
		}
		if (abort.PAbortCause == nil) != (cause == nil) || cause != nil && abort.PAbortCause.BigInt().Int64() != *cause {
			t.Fatal("P-Abort cause changed")
		}
	}
}

func internalCheckCode(t *testing.T, code Code, intent map[string]json.RawMessage) {
	t.Helper()
	if raw, ok := intent["local"]; ok {
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatal(err)
		}
		if code != LocalCode(n) {
			t.Fatalf("code %v, want local %d", code, n)
		}
	} else {
		var oid string
		if err := json.Unmarshal(intent["global"], &oid); err != nil {
			t.Fatal(err)
		}
		if code != GlobalCode(oid) {
			t.Fatalf("code %v, want global %s", code, oid)
		}
	}
}

func internalCheckDialogueIntent(t *testing.T, d *Dialogue, raw json.RawMessage) {
	t.Helper()
	if d == nil {
		t.Fatal("missing dialogue")
	}
	var expected struct {
		Type           string `json:"type"`
		VersionPresent bool   `json:"protocol_version_present"`
		ACN            OID    `json:"application_context_name"`
		Result         int64  `json:"result"`
		Diagnostic     struct {
			Kind  string `json:"kind"`
			Value int64  `json:"value"`
		} `json:"diagnostic"`
		AbortSource     int64 `json:"abort_source"`
		UserInformation []struct {
			DirectReference OID    `json:"direct_reference"`
			Single          string `json:"single_asn1_type_hex"`
		} `json:"user_information"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	var kind string
	var version *runtime.BitString
	var acn OID
	var ui []External
	switch {
	case d.Request != nil:
		kind, version, acn, ui = "AARQ", d.Request.ProtocolVersion, d.Request.ApplicationContextName, d.Request.UserInformation
	case d.Response != nil:
		kind, version, acn, ui = "AARE", d.Response.ProtocolVersion, d.Response.ApplicationContextName, d.Response.UserInformation
		if d.Response.Result.BigInt().Int64() != expected.Result {
			t.Fatal("AARE result changed")
		}
		diagnostic := d.Response.ResultSourceDiagnostic
		if expected.Diagnostic.Kind == "user" {
			if diagnostic.DialogueServiceUser == nil || diagnostic.DialogueServiceUser.BigInt().Int64() != expected.Diagnostic.Value {
				t.Fatal("user diagnostic changed")
			}
		} else if diagnostic.DialogueServiceProvider == nil || diagnostic.DialogueServiceProvider.BigInt().Int64() != expected.Diagnostic.Value {
			t.Fatal("provider diagnostic changed")
		}
	case d.Abort != nil:
		kind, ui = "ABRT", d.Abort.UserInformation
		if d.Abort.AbortSource.BigInt().Int64() != expected.AbortSource {
			t.Fatal("abort source changed")
		}
	case d.Unidirectional != nil:
		kind, version, acn, ui = "AUDT", d.Unidirectional.ProtocolVersion, d.Unidirectional.ApplicationContextName, d.Unidirectional.UserInformation
	}
	if kind != expected.Type || acn != expected.ACN || (version != nil) != expected.VersionPresent {
		t.Fatalf("dialogue %s, %s, %+v", kind, acn, version)
	}
	if version != nil && (version.BitLength != 1 || !bytes.Equal(version.Bytes, []byte{0x80})) {
		t.Fatal("version changed")
	}
	if len(ui) != len(expected.UserInformation) {
		t.Fatal("UI count changed")
	}
	for i, e := range ui {
		if e.DirectReference != expected.UserInformation[i].DirectReference || hex.EncodeToString(e.SingleASN1Type) != expected.UserInformation[i].Single {
			t.Fatalf("UI %d changed", i)
		}
	}
}

func TestInternalCaptures(t *testing.T) {
	for _, v := range internalVectors(t, "testdata/captures.json") {
		t.Run(v.Name, func(t *testing.T) {
			data := internalHex(t, v.Hex)
			m, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			out, err := m.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			expected := data
			if !bytes.Equal(expected, out) {
				if !strings.Contains(v.Name, "Camel-V2") {
					t.Fatalf("encoding differs: %x", out)
				}
				again, err := Parse(out)
				if err != nil || !reflect.DeepEqual(m, again) {
					t.Fatalf("round trip: %v", err)
				}
			}
		})
	}
}
