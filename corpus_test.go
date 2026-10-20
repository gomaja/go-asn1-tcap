package tcap_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// corpusVector is one entry of testdata/corpus.json (see testdata/README.md).
type corpusVector struct {
	ID              string         `json:"id"`
	Valid           bool           `json:"valid"`
	Hex             string         `json:"hex"`
	Intent          map[string]any `json:"intent"`
	WiresharkAgrees bool           `json:"wiresharkAgrees"`
	Notes           string         `json:"notes"`
}

func loadCorpus(t testing.TB) []corpusVector {
	t.Helper()
	data, err := os.ReadFile("testdata/corpus.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var vectors []corpusVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	return vectors
}

func corpusHex(t testing.TB, id string) string {
	t.Helper()
	for _, v := range loadCorpus(t) {
		if v.ID == id {
			return v.Hex
		}
	}
	t.Fatalf("corpus vector %q not found", id)
	return ""
}

// hx decodes a hex literal of the test tables; it panics on a typo so that a
// broken literal cannot pass silently.
func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad hex literal %q: %v", s, err))
	}
	return b
}

func ptr[T any](v T) *T { return &v }

func bigInt(v int64) *big.Int { return big.NewInt(v) }

// tlv builds the hex of one BER element with a definite length in the form
// ITU-T Q.773 (06/97) clause 4.1.1 requires: short form below 128, otherwise
// the long form with the minimum number of octets. TestTLVBuilder checks it
// against corpus vectors.
func tlv(tag string, parts ...string) string {
	content := strings.Join(parts, "")
	n := len(content) / 2
	var length string
	switch {
	case n < 0x80:
		length = fmt.Sprintf("%02x", n)
	case n <= 0xff:
		length = fmt.Sprintf("81%02x", n)
	case n <= 0xffff:
		length = fmt.Sprintf("82%04x", n)
	default:
		length = fmt.Sprintf("83%06x", n)
	}
	return tag + length + content
}

// Building blocks of the hand-built vectors, ITU-T Q.773 (06/97) Tables 8,
// 10, 13, 14, 19, 20, 22, 30-37 and 41-46.
const (
	hexOTID       = "480401020304"           // [APPLICATION 8] 01020304
	hexDTID       = "490405060708"           // [APPLICATION 9] 05060708
	hexDialogueAS = "060700118605010101"     // dialogue-as-id 0.0.17.773.1.1.1, Q.773 Table 37
	hexUniAS      = "060700118605010201"     // uniDialogue-as-id 0.0.17.773.1.2.1, Q.773 Table 36
	hexACN3       = "a109060704000001001403" // [1] 0.4.0.0.1.0.20.3
	hexPV1        = "80020780"               // [0] protocol-version {version1}, Q.773 Table 48
	hexInvoke     = "a10d02010102012d30050403010203"
	hexAARQ       = "600f" + hexPV1 + hexACN3
	hexAAREAcc    = "611b" + hexPV1 + hexACN3 + "a203020100" + "a305a103020100"
	hexAARERej    = "611b" + hexPV1 + hexACN3 + "a203020101" + "a305a103020102"
	hexABRTUser   = "6403800100"
	hexAUDT       = "600f" + hexPV1 + hexACN3
	hexOpaqueExt  = "280b06032a0304a0040402aabb" // EXTERNAL {1.2.3.4, single-ASN1-type 04 02 aa bb}
)

// dialoguePortion wraps a dialogue PDU in [APPLICATION 11] EXTERNAL
// {direct-reference, single-ASN1-type}, Q.773 Tables 30 to 33.
func dialoguePortion(as, pdu string) string {
	return tlv("6b", tlv("28", as, tlv("a0", pdu)))
}

func TestTLVBuilder(t *testing.T) {
	cases := []struct{ got, id string }{
		{tlv("62", hexOTID, tlv("6c", hexInvoke)), "begin-otid-4"},
		{tlv("62", hexOTID, dialoguePortion(hexDialogueAS, hexAARQ), tlv("6c", hexInvoke)), "begin-aarq-invoke"},
		{tlv("65", hexOTID, hexDTID, dialoguePortion(hexDialogueAS, hexAAREAcc), tlv("6c", "a20e020101300902012d30040402aabb")), "continue-first-backward-aare-result"},
		{tlv("61", dialoguePortion(hexUniAS, hexAUDT), tlv("6c", hexInvoke)), "unidirectional-audt-invoke"},
		{tlv("67", hexDTID, dialoguePortion(hexDialogueAS, "6403800101")), "abort-abrt-provider"},
		{tlv("62", hexOTID, tlv("6c", tlv("a1", "020101", "02012d", tlv("30", tlv("04", hex.EncodeToString(seq(140))))))), "begin-argument-140-octets"},
	}
	for _, c := range cases {
		if want := corpusHex(t, c.id); c.got != want {
			t.Errorf("%s:\n got %s\nwant %s", c.id, c.got, want)
		}
	}
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// ---------------------------------------------------------------------------
// Normalizer
//
// normalize turns a message into the JSON-like structure of the corpus
// `intent`. It renders every field of the message, so that two messages are
// equal exactly when their normalized forms are equal; it is also used by the
// aliasing, mutation and fuzz tests.
//
// Intent keys that are deliberately ignored (stripIntent):
//   - dialogue.single_asn1_type_hex for the structured and unidirectional
//     dialogue PDUs (AARQ, AARE, ABRT, AUDT): it is the encoding of the PDU,
//     not a field of tcap.Dialogue; the exact octets are checked by the
//     Marshal round trip, which must reproduce the vector.
//   - dialogue.user_information[].map_pdu, destinationReference,
//     originationReference, userSpecificReason: Wireshark's MAP decoding of
//     the user information value. This package carries that value as the
//     opaque single_asn1_type_hex, which is compared.
//   - trailing_hex, truncated_octets: they describe the defect of a negative
//     vector, not a decoded value.
// ---------------------------------------------------------------------------

func normalize(msg tcap.Message) map[string]any {
	switch m := msg.(type) {
	case *tcap.Begin:
		if m == nil {
			return map[string]any{"message_type": "nil begin"}
		}
		return map[string]any{
			"message_type": "begin",
			"otid":         hex.EncodeToString(m.OTID),
			"dialogue":     normDialogue(m.Dialogue),
			"components":   normComponents(m.Components),
		}
	case *tcap.Continue:
		if m == nil {
			return map[string]any{"message_type": "nil continue"}
		}
		return map[string]any{
			"message_type": "continue",
			"otid":         hex.EncodeToString(m.OTID),
			"dtid":         hex.EncodeToString(m.DTID),
			"dialogue":     normDialogue(m.Dialogue),
			"components":   normComponents(m.Components),
		}
	case *tcap.End:
		if m == nil {
			return map[string]any{"message_type": "nil end"}
		}
		return map[string]any{
			"message_type": "end",
			"dtid":         hex.EncodeToString(m.DTID),
			"dialogue":     normDialogue(m.Dialogue),
			"components":   normComponents(m.Components),
		}
	case *tcap.Abort:
		if m == nil {
			return map[string]any{"message_type": "nil abort"}
		}
		var cause any
		if m.PAbortCause != nil {
			cause = namedValue(*m.PAbortCause)
		}
		return map[string]any{
			"message_type":  "abort",
			"dtid":          hex.EncodeToString(m.DTID),
			"dialogue":      normDialogue(m.Dialogue),
			"components":    []any{},
			"p_abort_cause": cause,
		}
	case *tcap.Unidirectional:
		if m == nil {
			return map[string]any{"message_type": "nil unidirectional"}
		}
		return map[string]any{
			"message_type": "unidirectional",
			"dialogue":     normDialogue(m.Dialogue),
			"components":   normComponents(m.Components),
		}
	default:
		return map[string]any{"message_type": fmt.Sprintf("unexpected %T", msg)}
	}
}

type namedInteger interface {
	AsInt64() (int64, bool)
	BigInt() *big.Int
}

func namedValue(v namedInteger) any {
	if i, ok := v.AsInt64(); ok {
		return i
	}
	return v.BigInt().String()
}

func oidString(oid runtime.ObjectIdentifier) string {
	return oid.String()
}

func hexOrNil(b []byte) any {
	if b == nil {
		return nil
	}
	return hex.EncodeToString(b)
}

// protocolVersion renders a protocol-version: "version1" for an absent field
// (DEFAULT {version1}, Q.773 clause 3.2.1) and for only bit version1(0),
// including trailing zero named bits; anything else exactly.
func protocolVersion(pv *runtime.BitString) (present bool, value string) {
	if pv == nil {
		return false, "version1"
	}
	if pv.BitLength >= 1 && len(pv.Bytes) > 0 && pv.Bytes[0] == 0x80 {
		onlyVersion1 := true
		for _, octet := range pv.Bytes[1:] {
			if octet != 0 {
				onlyVersion1 = false
				break
			}
		}
		if onlyVersion1 {
			return true, "version1"
		}
	}
	return true, fmt.Sprintf("bits:%d:%x", pv.BitLength, pv.Bytes)
}

func normDialogue(d *tcap.Dialogue) any {
	if d == nil {
		return nil
	}
	set := 0
	for _, p := range []bool{d.Request != nil, d.Response != nil, d.Abort != nil, d.Unidirectional != nil, d.Opaque != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return map[string]any{"type": "invalid", "alternatives": set}
	}
	dialogueAS := oidString(wire.DialogueAsId())
	switch {
	case d.Request != nil:
		present, pv := protocolVersion(d.Request.ProtocolVersion)
		return map[string]any{
			"type":                     "AARQ",
			"direct_reference":         dialogueAS,
			"protocol_version_present": present,
			"protocol_version":         pv,
			"application_context_name": string(d.Request.ApplicationContextName),
			"user_information":         normUserInformation(d.Request.UserInformation),
		}
	case d.Response != nil:
		r := d.Response
		present, pv := protocolVersion(r.ProtocolVersion)
		return map[string]any{
			"type":                     "AARE",
			"direct_reference":         dialogueAS,
			"protocol_version_present": present,
			"protocol_version":         pv,
			"application_context_name": string(r.ApplicationContextName),
			"result":                   namedValue(r.Result),
			"diagnostic":               normDiagnostic(r.ResultSourceDiagnostic),
			"user_information":         normUserInformation(r.UserInformation),
		}
	case d.Abort != nil:
		return map[string]any{
			"type":             "ABRT",
			"direct_reference": dialogueAS,
			"abort_source":     namedValue(d.Abort.AbortSource),
			"user_information": normUserInformation(d.Abort.UserInformation),
		}
	case d.Unidirectional != nil:
		u := d.Unidirectional
		present, pv := protocolVersion(u.ProtocolVersion)
		return map[string]any{
			"type":                     "AUDT",
			"direct_reference":         oidString(wire.UniDialogueAsId()),
			"protocol_version_present": present,
			"protocol_version":         pv,
			"application_context_name": string(u.ApplicationContextName),
			"user_information":         normUserInformation(u.UserInformation),
		}
	default:
		ext := normExternal(*d.Opaque)
		ext["type"] = "opaque"
		return ext
	}
}

func normDiagnostic(d tcap.ResultSourceDiagnostic) any {
	switch {
	case d.DialogueServiceUser != nil && d.DialogueServiceProvider == nil:
		return map[string]any{"kind": "user", "value": namedValue(*d.DialogueServiceUser)}
	case d.DialogueServiceProvider != nil && d.DialogueServiceUser == nil:
		return map[string]any{"kind": "provider", "value": namedValue(*d.DialogueServiceProvider)}
	case d.DialogueServiceUser == nil:
		return map[string]any{"kind": "none"}
	default:
		return map[string]any{"kind": "both"}
	}
}

// normUserInformation renders absent and present-empty user information
// alike, as the corpus does; tests that care check nil explicitly.
func normUserInformation(ui []tcap.External) []any {
	out := []any{}
	for _, e := range ui {
		out = append(out, normExternal(e))
	}
	return out
}

func normExternal(e tcap.External) map[string]any {
	out := map[string]any{"direct_reference": string(e.DirectReference)}
	if e.IndirectReference != nil {
		out["indirect_reference"] = e.IndirectReference.String()
	}
	if e.DataValueDescriptor != nil {
		out["data_value_descriptor"] = *e.DataValueDescriptor
	}
	arbitrary := fmt.Sprintf("%d:%x", e.Arbitrary.BitLength, e.Arbitrary.Bytes)
	switch e.Encoding {
	case runtime.ExternalSingleASN1Type:
		out["single_asn1_type_hex"] = hex.EncodeToString(e.SingleASN1Type)
	case runtime.ExternalOctetAligned:
		out["octet_aligned_hex"] = hex.EncodeToString(e.OctetAligned)
	case runtime.ExternalArbitrary:
		out["arbitrary"] = arbitrary
	default:
		out["encoding"] = int(e.Encoding)
	}
	if e.Encoding != runtime.ExternalSingleASN1Type && len(e.SingleASN1Type) > 0 {
		out["single_asn1_type_hex"] = hex.EncodeToString(e.SingleASN1Type)
	}
	if e.Encoding != runtime.ExternalOctetAligned && len(e.OctetAligned) > 0 {
		out["octet_aligned_hex"] = hex.EncodeToString(e.OctetAligned)
	}
	if e.Encoding != runtime.ExternalArbitrary && (e.Arbitrary.BitLength != 0 || len(e.Arbitrary.Bytes) > 0) {
		out["arbitrary"] = arbitrary
	}
	return out
}

func normCode(c tcap.Code) any {
	switch v := c.(type) {
	case nil:
		return nil
	case tcap.LocalCode:
		return map[string]any{"local": int64(v)}
	case tcap.GlobalCode:
		return map[string]any{"global": string(v)}
	default:
		return map[string]any{"unexpected": fmt.Sprintf("%T", c)}
	}
}

func normComponents(cs []tcap.Component) []any {
	out := []any{}
	for _, c := range cs {
		out = append(out, normComponent(c))
	}
	return out
}

func optionalID(id *int64) any {
	if id == nil {
		return nil
	}
	return *id
}

func normReturnResult(kind string, r *tcap.ReturnResult) map[string]any {
	var result any
	if r.Result != nil {
		result = map[string]any{
			"opcode":        normCode(r.Result.OpCode),
			"parameter_hex": hexOrNil(r.Result.Parameter),
		}
	}
	return map[string]any{"type": kind, "invokeId": r.InvokeID, "result": result}
}

func normComponent(c tcap.Component) map[string]any {
	set := 0
	for _, p := range []bool{c.Invoke != nil, c.ReturnResultLast != nil, c.ReturnResultNotLast != nil, c.ReturnError != nil, c.Reject != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return map[string]any{"type": "invalid", "alternatives": set}
	}
	switch {
	case c.Invoke != nil:
		return map[string]any{
			"type":          "invoke",
			"invokeId":      c.Invoke.InvokeID,
			"linkedId":      optionalID(c.Invoke.LinkedID),
			"opcode":        normCode(c.Invoke.OpCode),
			"parameter_hex": hexOrNil(c.Invoke.Parameter),
		}
	case c.ReturnResultLast != nil:
		return normReturnResult("returnResultLast", c.ReturnResultLast)
	case c.ReturnResultNotLast != nil:
		return normReturnResult("returnResultNotLast", c.ReturnResultNotLast)
	case c.ReturnError != nil:
		return map[string]any{
			"type":          "returnError",
			"invokeId":      c.ReturnError.InvokeID,
			"errcode":       normCode(c.ReturnError.ErrorCode),
			"parameter_hex": hexOrNil(c.ReturnError.Parameter),
		}
	default:
		return map[string]any{
			"type":     "reject",
			"invokeId": optionalID(c.Reject.InvokeID),
			"problem":  normProblem(c.Reject.Problem),
		}
	}
}

func normProblem(p tcap.Problem) any {
	type alt struct {
		kind string
		v    namedInteger
	}
	var alts []alt
	if p.General != nil {
		alts = append(alts, alt{"general", *p.General})
	}
	if p.Invoke != nil {
		alts = append(alts, alt{"invoke", *p.Invoke})
	}
	if p.ReturnResult != nil {
		alts = append(alts, alt{"returnResult", *p.ReturnResult})
	}
	if p.ReturnError != nil {
		alts = append(alts, alt{"returnError", *p.ReturnError})
	}
	if len(alts) != 1 {
		return map[string]any{"kind": "invalid", "alternatives": len(alts)}
	}
	return map[string]any{"kind": alts[0].kind, "value": namedValue(alts[0].v)}
}

// canonicalJSON round-trips v through encoding/json so that values built by
// the normalizer and values decoded from the corpus compare alike.
func canonicalJSON(t testing.TB, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	return out
}

func jsonText(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(data)
}

// assertSameMessage fails unless a and b normalize to the same structure.
func assertSameMessage(t testing.TB, a, b tcap.Message) {
	t.Helper()
	na, nb := normalize(a), normalize(b)
	for _, value := range []any{na, nb} {
		if msg, ok := value.(map[string]any); ok {
			if d, ok := msg["dialogue"].(map[string]any); ok && d["protocol_version"] == "version1" {
				d["protocol_version_present"] = false
			}
		}
	}
	if !reflect.DeepEqual(canonicalJSON(t, na), canonicalJSON(t, nb)) {
		t.Errorf("messages differ:\n  %s\n  %s", jsonText(na), jsonText(nb))
	}
}

func stripIntent(intent map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range intent {
		if k == "trailing_hex" || k == "truncated_octets" {
			continue
		}
		out[k] = v
	}
	d, ok := out["dialogue"].(map[string]any)
	if !ok {
		return out
	}
	nd := map[string]any{}
	for k, v := range d {
		nd[k] = v
	}
	switch nd["type"] {
	case "AARQ", "AARE", "ABRT", "AUDT":
		delete(nd, "single_asn1_type_hex")
	}
	if ui, ok := nd["user_information"].([]any); ok {
		nui := []any{}
		for _, item := range ui {
			m, ok := item.(map[string]any)
			if !ok {
				nui = append(nui, item)
				continue
			}
			nm := map[string]any{}
			for k, v := range m {
				switch k {
				case "map_pdu", "destinationReference", "originationReference", "userSpecificReason":
				default:
					nm[k] = v
				}
			}
			nui = append(nui, nm)
		}
		nd["user_information"] = nui
	}
	out["dialogue"] = nd
	return out
}

// hasIndefiniteLength reports whether any element of data, at any depth of
// constructed nesting, uses the indefinite length form (ITU-T X.690 (02/2021)
// clause 8.1.3.6).
func hasIndefiniteLength(data []byte) (bool, error) {
	for i := 0; i < len(data); {
		tagByte := data[i]
		i++
		if tagByte&0x1f == 0x1f {
			for {
				if i >= len(data) {
					return false, errors.New("truncated tag")
				}
				b := data[i]
				i++
				if b&0x80 == 0 {
					break
				}
			}
		}
		if i >= len(data) {
			return false, errors.New("truncated length")
		}
		first := data[i]
		i++
		if first == 0x80 {
			return true, nil
		}
		n := int(first)
		if first&0x80 != 0 {
			k := int(first & 0x7f)
			if k > 4 || i+k > len(data) {
				return false, errors.New("bad long-form length")
			}
			n = 0
			for _, b := range data[i : i+k] {
				n = n<<8 | int(b)
			}
			i += k
		}
		if n > len(data)-i {
			return false, errors.New("truncated content")
		}
		if tagByte&0x20 != 0 {
			found, err := hasIndefiniteLength(data[i : i+n])
			if err != nil || found {
				return found, err
			}
		}
		i += n
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// Expected parse failures, contract section 6.
// ---------------------------------------------------------------------------

const unchecked = "?"

type parseErrWant struct {
	portions  []tcap.Portion     // any of
	msgTypes  []tcap.MessageType // any of; nil leaves it unchecked
	otid      string             // hex, "" for nil, unchecked for no check
	dtid      string             // hex, "" for nil, unchecked for no check
	compIndex *int               // nil leaves it unchecked
	invokeID  string             // decimal, "" for nil, unchecked for no check
	is        error              // sentinel reachable with errors.Is
	// constraint requires a *ber.ValidationError reachable with errors.As.
	constraint bool
	// noComponents requires ParseError.Components to be empty.
	noComponents bool
}

// asParseError returns err as a *tcap.ParseError, or fails the test.
func asParseError(t *testing.T, err error) *tcap.ParseError {
	t.Helper()
	pe, ok := err.(*tcap.ParseError)
	if !ok {
		t.Fatalf("error %T (%v) is not *tcap.ParseError", err, err)
	}
	return pe
}

func checkParseError(t *testing.T, err error, want parseErrWant) {
	t.Helper()
	if err == nil {
		t.Fatal("Parse succeeded, want *tcap.ParseError")
	}
	pe, ok := err.(*tcap.ParseError)
	if !ok {
		t.Fatalf("error %T (%v) is not *tcap.ParseError", err, err)
	}
	if pe.Error() == "" {
		t.Error("ParseError.Error() is empty")
	}
	if len(want.portions) > 0 {
		match := false
		for _, p := range want.portions {
			match = match || pe.Portion == p
		}
		if !match {
			t.Errorf("Portion = %q, want one of %q", pe.Portion, want.portions)
		}
	}
	if want.msgTypes != nil {
		match := false
		for _, m := range want.msgTypes {
			match = match || pe.MessageType == m
		}
		if !match {
			t.Errorf("MessageType = %q, want one of %q", pe.MessageType, want.msgTypes)
		}
	}
	checkTID := func(name string, got tcap.TransactionID, want string) {
		if want == unchecked {
			return
		}
		if want == "" {
			if got != nil {
				t.Errorf("%s = %x, want nil", name, []byte(got))
			}
			return
		}
		if hex.EncodeToString(got) != want || got == nil {
			t.Errorf("%s = %x, want %s", name, []byte(got), want)
		}
	}
	checkTID("OTID", pe.OTID, want.otid)
	checkTID("DTID", pe.DTID, want.dtid)
	if want.compIndex != nil && pe.ComponentIndex != *want.compIndex {
		t.Errorf("ComponentIndex = %d, want %d", pe.ComponentIndex, *want.compIndex)
	}
	switch want.invokeID {
	case unchecked:
	case "":
		if pe.InvokeID != nil {
			t.Errorf("InvokeID = %d, want nil", *pe.InvokeID)
		}
	default:
		if pe.InvokeID == nil || strconv.FormatInt(*pe.InvokeID, 10) != want.invokeID {
			t.Errorf("InvokeID = %v, want %s", optionalID(pe.InvokeID), want.invokeID)
		}
	}
	if want.is != nil && !errors.Is(err, want.is) {
		t.Errorf("errors.Is(%v, %v) = false", err, want.is)
	}
	if want.constraint {
		var ce *ber.ValidationError
		if !errors.As(err, &ce) {
			t.Errorf("error %v does not wrap *ber.ValidationError", err)
		}
	}
	if want.noComponents && len(pe.Components) != 0 {
		t.Errorf("Components = %s, want none", jsonText(normComponents(pe.Components)))
	}
}

var (
	idx0     = ptr(0)
	idxMinus = ptr(-1)
)

// corpusFailures lists, by vector id, the outcome contract section 6
// specifies for every vector that Parse rejects.
var corpusFailures = map[string]parseErrWant{
	// Q.773 Table 20 defines only the [0] Linked ID tag.
	"begin-linked-absent": {
		portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
		otid: "01020304", dtid: unchecked, compIndex: idx0, invokeID: "3", constraint: true,
		noComponents: true,
	},
	// OrigTransactionID SIZE (1..4), Q.773 clause 4.2.1.3.
	"negative-otid-0": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
		otid: "", dtid: unchecked, invokeID: unchecked, constraint: true,
	},
	"negative-otid-5": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
		otid: "", dtid: unchecked, invokeID: unchecked, constraint: true,
	},
	// DestTransactionID SIZE (1..4).
	"negative-dtid-zero": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{tcap.MessageTypeEnd},
		otid: unchecked, dtid: "", invokeID: unchecked, constraint: true,
	},
	"negative-dtid-five": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{tcap.MessageTypeEnd},
		otid: unchecked, dtid: "", invokeID: unchecked, constraint: true,
	},
	// ComponentPortion SIZE (1..MAX).
	"negative-empty-components": {
		portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
		otid: "01020304", dtid: unchecked, compIndex: idxMinus, invokeID: "", constraint: true,
		noComponents: true,
	},
	// Component ID range -128..127, Q.773 clause 4.2.2.2.
	"negative-invokeid-128": {
		portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
		otid: "01020304", dtid: unchecked, compIndex: idx0, invokeID: "", constraint: true, noComponents: true,
	},
	"negative-invokeid--129": {
		portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
		otid: "01020304", dtid: unchecked, compIndex: idx0, invokeID: "", constraint: true, noComponents: true,
	},
	// [APPLICATION 6] is not in Q.773 Table 8; OTID is still derivable (Q.774 Table 7, row UNKNOWN).
	"negative-unknown-message-tag": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{""},
		otid: "01020304", dtid: unchecked, invokeID: unchecked, is: tcap.ErrUnrecognizedMessageType,
	},
	"negative-trailing-octets": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
		otid: "01020304", dtid: unchecked, invokeID: unchecked,
	},
	// The outer TLV is incomplete, so whether its tag still names the message
	// type is left open.
	"negative-truncated-message": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin, ""},
		otid: unchecked, dtid: unchecked, invokeID: unchecked,
	},
	// single-ASN1-type [0] is EXPLICIT, so constructed: ITU-T X.690 (02/2021) clause 8.18.
	"negative-primitive-single-asn1-type": {
		portions: []tcap.Portion{tcap.PortionDialogue}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
		otid: "01020304", dtid: unchecked, invokeID: unchecked,
	},
	// ITU-T Q.774 (06/97) Table 3: an Abort carries no AARQ.
	"negative-abort-aarq": {
		portions: []tcap.Portion{tcap.PortionDialogue}, msgTypes: []tcap.MessageType{tcap.MessageTypeAbort},
		otid: unchecked, dtid: "05060708", invokeID: unchecked, is: tcap.ErrUnexpectedDialoguePDU,
	},
	// The component portion of a Unidirectional is mandatory (Q.773 Table 3).
	"negative-unidirectional-no-components": {
		portions: []tcap.Portion{tcap.PortionComponent, tcap.PortionTransaction},
		msgTypes: []tcap.MessageType{tcap.MessageTypeUnidirectional},
		otid:     unchecked, dtid: unchecked, invokeID: unchecked,
	},
	// P-AbortCause INTEGER (0..127), Q.773 clause 3.1.
	"negative-p-abort-cause-128": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{tcap.MessageTypeAbort},
		otid: unchecked, dtid: "05060708", invokeID: unchecked, constraint: true,
	},
	"negative-p-abort-cause-minus-one": {
		portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{tcap.MessageTypeAbort},
		otid: unchecked, dtid: "05060708", invokeID: unchecked, constraint: true,
	},
}

// indefiniteCounterparts maps each vector that uses indefinite lengths to
// the canonical vector encoding the same values (compare the intents).
var indefiniteCounterparts = map[string]string{
	"begin-indefinite-components-invoke": "begin-otid-4",
	"begin-indefinite-outer":             "begin-otid-4",
}

func TestCorpusInventory(t *testing.T) {
	vectors := loadCorpus(t)
	if len(vectors) != 67 {
		t.Errorf("corpus has %d vectors, testdata/README.md says 67", len(vectors))
	}
	seen := map[string]bool{}
	for _, v := range vectors {
		if seen[v.ID] {
			t.Errorf("duplicate id %s", v.ID)
		}
		seen[v.ID] = true
		if _, listed := corpusFailures[v.ID]; !v.Valid && !listed {
			t.Errorf("negative vector %s has no expected outcome", v.ID)
		}
		if _, err := hex.DecodeString(v.Hex); err != nil {
			t.Errorf("%s: %v", v.ID, err)
		}
	}
	for id := range corpusFailures {
		if !seen[id] {
			t.Errorf("expected failure for unknown vector %s", id)
		}
	}
	for id, canon := range indefiniteCounterparts {
		if !seen[id] || !seen[canon] {
			t.Errorf("unknown vector in indefiniteCounterparts: %s -> %s", id, canon)
		}
	}
}

func TestCorpusValidVectors(t *testing.T) {
	for _, v := range loadCorpus(t) {
		if _, fails := corpusFailures[v.ID]; fails || !v.Valid {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			data := hx(v.Hex)
			msg, err := tcap.Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := canonicalJSON(t, normalize(msg))
			want := canonicalJSON(t, stripIntent(v.Intent))
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("parsed value differs from intent:\n got %s\nwant %s", jsonText(got), jsonText(want))
			}
			checkAbsentPortions(t, msg)

			out, err := msg.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if canon, ok := indefiniteCounterparts[v.ID]; ok {
				// Contract section 6: same value as the canonical
				// counterpart, Marshal emits definite lengths.
				if indef, err := hasIndefiniteLength(out); err != nil || indef {
					t.Errorf("Marshal output %x: indefinite=%v err=%v", out, indef, err)
				}
				if want := corpusHex(t, canon); hex.EncodeToString(out) != want {
					t.Errorf("Marshal:\n got %x\nwant %s (%s)", out, want, canon)
				}
				again, err := tcap.Parse(out)
				if err != nil {
					t.Fatalf("Parse(Marshal): %v", err)
				}
				assertSameMessage(t, msg, again)
				return
			}
			if hex.EncodeToString(out) != corpusHex(t, v.ID) {
				t.Errorf("Marshal:\n got %x\nwant %s", out, corpusHex(t, v.ID))
			}
		})
	}
}

// checkAbsentPortions checks that what the corpus vectors leave out is nil:
// no valid message has a present but empty component portion (SIZE (1..MAX)),
// and no corpus vector carries a present but empty user-information field,
// so an empty slice there must be a nil one (contract 4.3).
func checkAbsentPortions(t *testing.T, msg tcap.Message) {
	t.Helper()
	var comps []tcap.Component
	var d *tcap.Dialogue
	switch m := msg.(type) {
	case *tcap.Begin:
		comps, d = m.Components, m.Dialogue
	case *tcap.Continue:
		comps, d = m.Components, m.Dialogue
	case *tcap.End:
		comps, d = m.Components, m.Dialogue
	case *tcap.Unidirectional:
		comps, d = m.Components, m.Dialogue
	case *tcap.Abort:
		d = m.Dialogue
	}
	if comps != nil && len(comps) == 0 {
		t.Error("Components is non-nil and empty for an absent component portion")
	}
	if d == nil {
		return
	}
	var ui []tcap.External
	switch {
	case d.Request != nil:
		ui = d.Request.UserInformation
	case d.Response != nil:
		ui = d.Response.UserInformation
	case d.Abort != nil:
		ui = d.Abort.UserInformation
	case d.Unidirectional != nil:
		ui = d.Unidirectional.UserInformation
	}
	if ui != nil && len(ui) == 0 {
		t.Error("UserInformation is non-nil and empty for an absent user-information field")
	}
}

func TestCorpusExpectedFailures(t *testing.T) {
	for _, v := range loadCorpus(t) {
		want, ok := corpusFailures[v.ID]
		if !ok {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			msg, err := tcap.Parse(hx(v.Hex))
			if msg != nil {
				t.Errorf("Parse returned a message %s with the error", jsonText(normalize(msg)))
			}
			checkParseError(t, err, want)
		})
	}
}

// TestCorpusTolerance covers WithTolerance (parse.go) and
// contract section 6: values outside their ASN.1 constraints parse, each
// violation is recorded, and Marshal stays strict.
func TestCorpusTolerance(t *testing.T) {
	cases := []struct {
		id         string
		violations int // exact count; 0 means at least one
		check      func(t *testing.T, msg tcap.Message)
	}{
		{"negative-otid-5", 1, func(t *testing.T, msg tcap.Message) {
			b, ok := msg.(*tcap.Begin)
			if !ok || hex.EncodeToString(b.OTID) != "0102030405" {
				t.Errorf("got %s, want Begin with OTID 0102030405", jsonText(normalize(msg)))
			}
		}},
		{"negative-dtid-five", 1, func(t *testing.T, msg tcap.Message) {
			e, ok := msg.(*tcap.End)
			if !ok || hex.EncodeToString(e.DTID) != "0102030405" {
				t.Errorf("got %s, want End with DTID 0102030405", jsonText(normalize(msg)))
			}
		}},
		{"negative-invokeid-128", 0, func(t *testing.T, msg tcap.Message) {
			b, ok := msg.(*tcap.Begin)
			if !ok || len(b.Components) != 1 || b.Components[0].Invoke == nil || b.Components[0].Invoke.InvokeID != 128 {
				t.Errorf("got %s, want Begin with invoke ID 128", jsonText(normalize(msg)))
			}
		}},
		{"negative-invokeid--129", 0, func(t *testing.T, msg tcap.Message) {
			b, ok := msg.(*tcap.Begin)
			if !ok || len(b.Components) != 1 || b.Components[0].Invoke == nil || b.Components[0].Invoke.InvokeID != -129 {
				t.Errorf("got %s, want Begin with invoke ID -129", jsonText(normalize(msg)))
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			var log ber.ViolationLog
			msg, err := tcap.Parse(hx(corpusHex(t, c.id)), tcap.WithTolerance(&log))
			if err != nil {
				t.Fatalf("Parse with tolerance: %v", err)
			}
			got := len(log.Snapshot())
			if (c.violations == 0 && got == 0) || (c.violations > 0 && got != c.violations) {
				t.Errorf("recorded %d violations (%+v), want %d (0 = at least one)", got, log.Snapshot(), c.violations)
			}
			c.check(t, msg)
			_, err = msg.Marshal()
			var ce *ber.ValidationError
			if !errors.As(err, &ce) {
				t.Errorf("Marshal error = %v, want *ber.ValidationError", err)
			}
		})
	}

	// Contract section 6 leaves open whether the codec tolerates SIZE 0;
	// either outcome must be consistent.
	t.Run("negative-otid-0", func(t *testing.T) {
		var log ber.ViolationLog
		msg, err := tcap.Parse(hx(corpusHex(t, "negative-otid-0")), tcap.WithTolerance(&log))
		if err != nil {
			if _, ok := err.(*tcap.ParseError); !ok {
				t.Fatalf("error %T is not *tcap.ParseError", err)
			}
			if n := len(log.Snapshot()); n != 0 {
				t.Errorf("failed Parse recorded %d violations", n)
			}
			t.Logf("SIZE 0 not tolerated: %v", err)
			return
		}
		b, ok := msg.(*tcap.Begin)
		if !ok || len(b.OTID) != 0 {
			t.Errorf("got %s, want Begin with empty OTID", jsonText(normalize(msg)))
		}
		if len(log.Snapshot()) == 0 {
			t.Error("no violation recorded")
		}
		_, err = msg.Marshal()
		var ce *ber.ValidationError
		if !errors.As(err, &ce) {
			t.Errorf("Marshal error = %v, want *ber.ValidationError", err)
		}
		t.Logf("SIZE 0 tolerated, %d violation(s)", len(log.Snapshot()))
	})

	// An OTID of 5 octets and an invoke ID of 128: both violations are
	// tolerated and recorded.
	t.Run("two-violations", func(t *testing.T) {
		var log ber.ViolationLog
		if _, err := tcap.Parse(hx("6219480501020304056c10a10e0202008002012d30050403010203"), tcap.WithTolerance(&log)); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if n := len(log.Snapshot()); n < 2 {
			t.Errorf("recorded %d violations, want at least 2", n)
		}
	})

	// "The violations are recorded only if Parse succeeds" (parse.go).
	failing := []struct{ name, hex string }{
		// OTID of 5 octets in a message truncated by one octet.
		{"truncated", "6218480501020304056c0fa10d02010102012d300504030102"},
		// OTID of 5 octets and a linked ID encoded as [1] NULL (Q.773 Table 20).
		{"linked-absent", "6213480501020304056c0aa108020103810002013c"},
	}
	for _, f := range failing {
		t.Run("nothing-recorded-"+f.name, func(t *testing.T) {
			var log ber.ViolationLog
			_, err := tcap.Parse(hx(f.hex), tcap.WithTolerance(&log))
			if _, ok := err.(*tcap.ParseError); !ok {
				t.Fatalf("error = %v (%T), want *tcap.ParseError", err, err)
			}
			if n := len(log.Snapshot()); n != 0 {
				t.Errorf("failed Parse recorded %d violations: %+v", n, log.Snapshot())
			}
		})
	}
}
