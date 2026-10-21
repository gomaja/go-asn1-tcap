package tcap_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

func mustParse(t *testing.T, s string) tcap.Message {
	t.Helper()
	msg, err := tcap.Parse(hx(s))
	if err != nil {
		t.Fatalf("Parse %s: %v", s, err)
	}
	return msg
}

func mustMarshal(t *testing.T, msg tcap.Message) []byte {
	t.Helper()
	out, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return out
}

func messageDialogue(msg tcap.Message) *tcap.Dialogue {
	switch m := msg.(type) {
	case *tcap.Begin:
		return m.Dialogue
	case *tcap.Continue:
		return m.Dialogue
	case *tcap.End:
		return m.Dialogue
	case *tcap.Abort:
		return m.Dialogue
	case *tcap.Unidirectional:
		return m.Dialogue
	}
	return nil
}

// WithTolerance accepts valid BER outside the Q.773 (06/97) clause 4.1.1
// profile and records the violations. Fresh encodings use the profile.
func TestParseAcceptsGenericBER(t *testing.T) {
	otid4 := corpusHex(t, "begin-otid-4")
	aarq := corpusHex(t, "begin-aarq-invoke")
	cases := []struct{ name, input, canonical string }{
		{"message length long form 1 octet", "6281174804010203046c0fa10d02010102012d30050403010203", otid4},
		{"message length long form 2 octets", "628200174804010203046c0fa10d02010102012d30050403010203", otid4},
		{"OTID length long form 1 octet", "6218488104010203046c0fa10d02010102012d30050403010203", otid4},
		{"OTID length long form 2 octets", "621948820004010203046c0fa10d02010102012d30050403010203", otid4},
		// X.690 (02/2021) clause 8.7.3: constructed OCTET STRING.
		{"constructed OTID", "621968060404010203046c0fa10d02010102012d30050403010203", otid4},
		{"constructed OTID two segments", "621b680804020102040203046c0fa10d02010102012d30050403010203", otid4},
		{"constructed OTID indefinite", "621b688004040102030400006c0fa10d02010102012d30050403010203", otid4},
		{"component portion and component lengths long form", "621a4804010203046c820010a1810d02010102012d30050403010203", otid4},
		{"invoke ID and operation code lengths long form", "62194804010203046c11a10f028101010281012d30050403010203", otid4},
		{"every constructed element indefinite", "62804804010203046c80a18002010102012d30050403010203000000000000", otid4},
		{"dialogue lengths long form", "623f4804010203046b812528812206810700118605010101a081156081128081020780a1810a068107040000010014036c0fa10d02010102012d30050403010203", aarq},
		// X.690 (02/2021) clause 8.6.3: constructed BIT STRING.
		{"constructed protocol-version", "62394804010203046b20281e060700118605010101a0136011a00403020780a1090607040000010014036c0fa10d02010102012d30050403010203", aarq},
		{"dialogue elements indefinite", "62414804010203046b802880060700118605010101a080608080020780a180060704000001001403000000000000000000006c0fa10d02010102012d30050403010203", aarq},
		// Contract 4.2: the data value of a known PDU may be octet-aligned
		// or arbitrary with whole octets; Marshal uses single-ASN1-type.
		{"AARQ as octet-aligned", "62374804010203046b1e281c0607001186050101018111600f80020780a1090607040000010014036c0fa10d02010102012d30050403010203", aarq},
		{"AARQ as arbitrary", "62384804010203046b1f281d060700118605010101821200600f80020780a1090607040000010014036c0fa10d02010102012d30050403010203", aarq},
		{"user information lengths long form and indefinite",
			"62684804010203046b432841060700118605010101a036603480020780a109060704000001001403be8028811e06810704000001010101a080a00e800591214365f7810591769810f2000000006c1ba11902010102012d3011800591214365f78101ff820591769810f2",
			corpusHex(t, "begin-aarq-map-open")},
		{"user information constructed octet-aligned",
			"62374804010203046b2f282d060700118605010101a022602080020780a109060704000001001403be0f280d06032a0304a106040101040102",
			"62334804010203046b2b2829060700118605010101a01e601c80020780a109060704000001001403be0b280906032a030481020102"},
		{"lengths of 128 and more with an extra octet",
			"628200a54804010203046c82009b" + corpusHex(t, "begin-argument-140-octets")[24:],
			corpusHex(t, "begin-argument-140-octets")},
		{"P-Abort cause length long form, constructed DTID", "670c69060404050607084a810101", corpusHex(t, "abort-p-cause-1")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.input == c.canonical {
				t.Fatal("input is already canonical")
			}
			_, strict := tcap.Parse(hx(c.input))
			permitted := c.name == "every constructed element indefinite" || c.name == "dialogue elements indefinite" || c.name == "AARQ as octet-aligned" || c.name == "AARQ as arbitrary"
			var validation *ber.ValidationError
			if permitted && strict != nil || !permitted && !errors.As(strict, &validation) {
				t.Fatalf("strict Parse: %v", strict)
			}
			var reports ber.ViolationLog
			msg, err := tcap.Parse(hx(c.input), tcap.WithTolerance(&reports))
			if err != nil {
				t.Fatal(err)
			}
			if !permitted && len(reports.Snapshot()) == 0 {
				t.Fatal("profile violation was not reported")
			}
			assertSameMessage(t, msg, mustParse(t, c.canonical))
			if out := hex.EncodeToString(mustMarshal(t, msg)); out != c.canonical {
				t.Errorf("Marshal: got %s; want %s", out, c.canonical)
			}
		})
	}
}

// Parameters retain their BER bytes in both modes (ITU-T X.690 (02/2021)
// clause 8.15); Q.773 clause 4.1.1 applies to TCAP's own syntax.
func TestParseParameterVerbatim(t *testing.T) {
	cases := []struct{ name, input, param string }{
		{"inner length not minimal", "62184804010203046c10a10e02010102012d3006048103010203", "3006048103010203"},
		{"outer length not minimal", "62184804010203046c10a10e02010102012d3081050403010203", "3081050403010203"},
		{"outer length indefinite", "62194804010203046c11a10f02010102012d308004030102030000", "308004030102030000"},
		{"corpus begin-nonminimal-long-length", corpusHex(t, "begin-nonminimal-long-length"), "30820006048103010203"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var reports ber.ViolationLog
			msg, err := tcap.Parse(hx(c.input), tcap.WithTolerance(&reports))
			if err != nil {
				t.Fatal(err)
			}
			strict, err := tcap.Parse(hx(c.input))
			if err != nil || len(reports.Snapshot()) != 0 {
				t.Fatalf("strict Parse: %v; reports %v", err, reports.Snapshot())
			}
			assertSameMessage(t, msg, strict)
			b, ok := msg.(*tcap.Begin)
			if !ok || len(b.Components) != 1 || b.Components[0].Invoke == nil {
				t.Fatalf("parsed %s", jsonText(normalize(msg)))
			}
			if got := hex.EncodeToString(b.Components[0].Invoke.Parameter); got != c.param {
				t.Errorf("Parameter = %s, want %s", got, c.param)
			}
			out, err := msg.Marshal()
			if err != nil || hex.EncodeToString(out) != c.input {
				t.Fatalf("Marshal = %x, %v", out, err)
			}
			again, err := tcap.Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			assertSameMessage(t, msg, again)
		})
	}
}

// TestParseOpaqueDialogue: a dialogue portion in an abstract syntax other
// than dialogue-as-id and uniDialogue-as-id is kept as an opaque EXTERNAL,
// every field exactly. Unresolved identification and Unidirectional syntax
// violations require tolerance (Q.773 clause 4.2.3). Begin requires AARQ in
// both modes (Q.774 Figure A.5, sheet 3).
func TestParseOpaqueDialogue(t *testing.T) {
	cases := []struct {
		name, input string
		want        tcap.External
	}{
		{"single-ASN1-type", "62264804010203046b0d280b06032a0304a0040402aabb6c0fa10d02010102012d30050403010203",
			tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: hx("0402aabb")}},
		{"all identification fields, octet-aligned", "621c4804010203046b14281206032a030402010507036162638103010203",
			tcap.External{DirectReference: "1.2.3.4", IndirectReference: bigInt(5), DataValueDescriptor: ptr("abc"), Encoding: runtime.ExternalOctetAligned, OctetAligned: hx("010203")}},
		{"arbitrary with unused bits", "62134804010203046b0b280906032a0304820204f0",
			tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalArbitrary, Arbitrary: runtime.BitString{Bytes: hx("f0"), BitLength: 4}}},
		{"indirect reference only, in an Abort", "67114904050607086b092807020107a0020500",
			tcap.External{IndirectReference: bigInt(7), Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: hx("0500")}},
		{"in a Continue", tlv("65", hexOTID, hexDTID, tlv("6b", hexOpaqueExt)), *opaqueE()},
		{"in an End", tlv("64", hexDTID, tlv("6b", hexOpaqueExt)), *opaqueE()},
		{"in a Unidirectional", tlv("61", tlv("6b", hexOpaqueExt), tlv("6c", hexInvoke)), *opaqueE()},
	}
	// Keep field-preservation coverage in End, where Opaque is permitted.
	for _, c := range cases[:3] {
		c.name = "End/" + c.name
		c.input = "64" + c.input[2:4] + "49" + c.input[6:]
		cases = append(cases, c)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, strict := tcap.Parse(hx(c.input))
			begin := hx(c.input)[0] == 0x62
			nonconforming := c.want.IndirectReference != nil || c.name == "in a Unidirectional"
			var validation *ber.ValidationError
			if nonconforming && !errors.As(strict, &validation) || !nonconforming && begin && !errors.Is(strict, tcap.ErrUnexpectedDialoguePDU) || !nonconforming && !begin && strict != nil {
				t.Fatalf("strict Parse = %v", strict)
			}
			var reports ber.ViolationLog
			msg, err := tcap.Parse(hx(c.input), tcap.WithTolerance(&reports))
			if begin {
				var pe *tcap.ParseError
				if msg != nil || !errors.Is(err, tcap.ErrUnexpectedDialoguePDU) || !errors.As(err, &pe) || pe.Portion != tcap.PortionDialogue || len(reports.Snapshot()) != 0 {
					t.Fatalf("Begin/Opaque = %v, %v, reports %v", msg, err, reports.Snapshot())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if nonconforming && len(reports.Snapshot()) == 0 {
				t.Fatal("no violation reported")
			}
			d := messageDialogue(msg)
			if d == nil || d.Opaque == nil || d.Request != nil || d.Response != nil || d.Abort != nil || d.Unidirectional != nil {
				t.Fatalf("dialogue %s, want only Opaque", jsonText(normDialogue(d)))
			}
			got, want := canonicalJSON(t, normExternal(*d.Opaque)), canonicalJSON(t, normExternal(c.want))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Opaque:\n got %s\nwant %s", jsonText(got), jsonText(want))
			}
			out, err := msg.Marshal()
			if nonconforming {
				if !errors.As(err, &validation) {
					t.Fatalf("strict Marshal = %x, %v", out, err)
				}
			} else if err != nil || hex.EncodeToString(out) != c.input {
				t.Fatalf("Marshal = %x, %v", out, err)
			}
		})
	}
}

// TestParseKnownDialogueErrors: a known abstract syntax whose data value is
// not a PDU of that syntax, or is not whole octets, is an error in the
// dialogue portion, with no fallback to Opaque (contract 4.2).
func TestParseKnownDialogueErrors(t *testing.T) {
	cases := []struct{ name, input string }{
		// 04 01 00 is no DialoguePDU (Q.773 clause 3.2.1).
		{"dialogue-as-id with an OCTET STRING", "62294804010203046b10280e060700118605010101a0030401006c0fa10d02010102012d30050403010203"},
		// An AARQ as an arbitrary value with 2 unused bits.
		{"arbitrary with unused bits", "62384804010203046b1f281d060700118605010101821202600f80020780a1090607040000010014046c0fa10d02010102012d30050403010203"},
		// uniDialogue-as-id defines only the AUDT (Q.773 clause 3.2.2).
		{"AARE under uniDialogue-as-id", tlv("61", dialoguePortion(hexUniAS, hexAAREAcc), tlv("6c", hexInvoke))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := tcap.Parse(hx(c.input))
			checkParseError(t, err, parseErrWant{portions: []tcap.Portion{tcap.PortionDialogue}, otid: unchecked, dtid: unchecked, invokeID: unchecked})
		})
	}
}

// TestParseDialoguePlacement is ITU-T Q.774 (06/97) Table 3 on receipt
// (contract 4.2): every dialogue PDU in every message type.
func TestParseDialoguePlacement(t *testing.T) {
	pdus := []struct{ name, dp string }{
		{"AARQ", dialoguePortion(hexDialogueAS, hexAARQ)},
		{"AARE accepted", dialoguePortion(hexDialogueAS, hexAAREAcc)},
		{"AARE rejected", dialoguePortion(hexDialogueAS, hexAARERej)},
		{"ABRT", dialoguePortion(hexDialogueAS, hexABRTUser)},
		{"AUDT", dialoguePortion(hexUniAS, hexAUDT)},
	}
	inv := tlv("6c", hexInvoke)
	messages := []struct {
		mt    tcap.MessageType
		build func(dp string) string
		otid  string
		dtid  string
	}{
		{tcap.MessageTypeBegin, func(dp string) string { return tlv("62", hexOTID, dp, inv) }, "01020304", unchecked},
		{tcap.MessageTypeContinue, func(dp string) string { return tlv("65", hexOTID, hexDTID, dp, inv) }, "01020304", "05060708"},
		{tcap.MessageTypeEnd, func(dp string) string { return tlv("64", hexDTID, dp, inv) }, unchecked, "05060708"},
		{tcap.MessageTypeAbort, func(dp string) string { return tlv("67", hexDTID, dp) }, unchecked, "05060708"},
		{tcap.MessageTypeUnidirectional, func(dp string) string { return tlv("61", dp, inv) }, unchecked, unchecked},
	}
	// outcome: "" accepted, otherwise the sentinel.
	outcome := map[tcap.MessageType]map[string]error{
		tcap.MessageTypeBegin:          {"AARE accepted": tcap.ErrUnexpectedDialoguePDU, "AARE rejected": tcap.ErrUnexpectedDialoguePDU, "ABRT": tcap.ErrUnexpectedDialoguePDU, "AUDT": tcap.ErrUnexpectedDialoguePDU},
		tcap.MessageTypeContinue:       {"AARQ": tcap.ErrUnexpectedDialoguePDU, "AARE rejected": tcap.ErrUnexpectedDialogueResult, "ABRT": tcap.ErrUnexpectedDialoguePDU, "AUDT": tcap.ErrUnexpectedDialoguePDU},
		tcap.MessageTypeEnd:            {"AARQ": tcap.ErrUnexpectedDialoguePDU, "AARE rejected": tcap.ErrUnexpectedDialogueResult, "ABRT": tcap.ErrUnexpectedDialoguePDU, "AUDT": tcap.ErrUnexpectedDialoguePDU},
		tcap.MessageTypeAbort:          {"AARQ": tcap.ErrUnexpectedDialoguePDU, "AARE accepted": tcap.ErrUnexpectedDialogueResult, "AUDT": tcap.ErrUnexpectedDialoguePDU},
		tcap.MessageTypeUnidirectional: {"AARQ": tcap.ErrUnexpectedDialoguePDU, "AARE accepted": tcap.ErrUnexpectedDialoguePDU, "AARE rejected": tcap.ErrUnexpectedDialoguePDU, "ABRT": tcap.ErrUnexpectedDialoguePDU},
	}
	for _, m := range messages {
		for _, p := range pdus {
			t.Run(string(m.mt)+"/"+p.name, func(t *testing.T) {
				input := m.build(p.dp)
				msg, err := tcap.Parse(hx(input))
				want := outcome[m.mt][p.name]
				if want == nil {
					if err != nil {
						t.Fatalf("Parse: %v", err)
					}
					if out := hex.EncodeToString(mustMarshal(t, msg)); out != input {
						t.Errorf("Marshal:\n got %s\nwant %s", out, input)
					}
					return
				}
				expected := parseErrWant{portions: []tcap.Portion{tcap.PortionDialogue}, msgTypes: []tcap.MessageType{m.mt}, otid: m.otid, dtid: m.dtid, invokeID: unchecked, is: want}
				checkParseError(t, err, expected)
			})
		}
	}
}

// TestParseProtocolVersion: the protocol-version of an AARQ or an AUDT is
// kept exactly, the stack answers it (Q.774 clause 3.2.3); an AARE carries
// exactly version1 (contract 4.2).
func TestParseProtocolVersion(t *testing.T) {
	requests := []struct {
		name, input string
		bytes       string
		bitLength   int
		offers      bool
	}{
		{"version1 and bit 1", "62374804010203046b1e281c060700118605010101a011600f800206c0a1090607040000010014036c0fa10d02010102012d30050403010203", "c0", 2, true},
		{"version1 with trailing zero bits", "62374804010203046b1e281c060700118605010101a011600f80020080a1090607040000010014036c0fa10d02010102012d30050403010203", "80", 8, true},
		{"only bit 1", "62374804010203046b1e281c060700118605010101a011600f80020640a1090607040000010014036c0fa10d02010102012d30050403010203", "40", 2, false},
		{"empty", "62364804010203046b1d281b060700118605010101a010600e800100a1090607040000010014036c0fa10d02010102012d30050403010203", "", 0, false},
	}
	for _, c := range requests {
		t.Run("AARQ "+c.name, func(t *testing.T) {
			msg := mustParse(t, c.input)
			d := messageDialogue(msg)
			if d == nil || d.Request == nil {
				t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
			}
			wantBits(t, "protocol-version", d.Request.ProtocolVersion, c.bytes, c.bitLength)
			if got := tcap.OffersVersion1(d.Request.ProtocolVersion); got != c.offers {
				t.Errorf("OffersVersion1 = %v, want %v", got, c.offers)
			}
			out, err := msg.Marshal()
			if c.offers {
				if err != nil || hex.EncodeToString(out) != c.input {
					t.Errorf("Marshal = %x, %v; want %s", out, err, c.input)
				}
			} else if !errors.Is(err, tcap.ErrUnsupportedProtocolVersion) {
				t.Errorf("Marshal error = %v, want ErrUnsupportedProtocolVersion", err)
			}
		})
	}
	t.Run("AARQ absent", func(t *testing.T) {
		d := messageDialogue(mustParse(t, corpusHex(t, "begin-aarq-default-version")))
		if d == nil || d.Request == nil || d.Request.ProtocolVersion != nil || !tcap.OffersVersion1(d.Request.ProtocolVersion) {
			t.Errorf("dialogue %s", jsonText(normDialogue(d)))
		}
	})
	t.Run("AUDT only bit 1", func(t *testing.T) {
		msg := mustParse(t, "61316b1e281c060700118605010201a011600f80020640a1090607040000010014036c0fa10d02010102012d30050403010203")
		d := messageDialogue(msg)
		if d == nil || d.Unidirectional == nil {
			t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
		}
		wantBits(t, "protocol-version", d.Unidirectional.ProtocolVersion, "40", 2)
		if tcap.OffersVersion1(d.Unidirectional.ProtocolVersion) {
			t.Error("OffersVersion1 = true")
		}
		if _, err := msg.Marshal(); !errors.Is(err, tcap.ErrUnsupportedProtocolVersion) {
			t.Errorf("Marshal error = %v, want ErrUnsupportedProtocolVersion", err)
		}
	})
	responses := []struct{ name, input string }{
		{"version1 and bit 1", "65384804010203044904050607086b2a2828060700118605010101a01d611b800206c0a109060704000001001403a203020100a305a103020100"},
		{"only bit 1", "65384804010203044904050607086b2a2828060700118605010101a01d611b80020640a109060704000001001403a203020100a305a103020100"},
		{"empty", "65374804010203044904050607086b292827060700118605010101a01c611a800100a109060704000001001403a203020100a305a103020100"},
	}
	for _, c := range responses {
		t.Run("AARE "+c.name, func(t *testing.T) {
			_, err := tcap.Parse(hx(c.input))
			checkParseError(t, err, parseErrWant{
				portions: []tcap.Portion{tcap.PortionDialogue}, msgTypes: []tcap.MessageType{tcap.MessageTypeContinue},
				otid: "01020304", dtid: "05060708", invokeID: unchecked, is: tcap.ErrUnsupportedProtocolVersion,
			})
		})
	}
	// Marshal emits this AARE (contract 3.9 allows trailing zero bits), so
	// Parse accepts it back.
	t.Run("AARE version1 with trailing zero bits", func(t *testing.T) {
		const input = "65384804010203044904050607086b2a2828060700118605010101a01d611b80020080a109060704000001001403a203020100a305a103020100"
		msg := mustParse(t, input)
		d := messageDialogue(msg)
		if d == nil || d.Response == nil {
			t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
		}
		wantBits(t, "protocol-version", d.Response.ProtocolVersion, "80", 8)
		if out := hex.EncodeToString(mustMarshal(t, msg)); out != input {
			t.Errorf("Marshal:\n got %s\nwant %s", out, input)
		}
	})
}

// TestParseUserInformation: user information keeps order, absent versus
// present-empty, and every EXTERNAL field (contract 4.2 and 4.3).
func TestParseUserInformation(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		d := messageDialogue(mustParse(t, corpusHex(t, "begin-aarq-invoke")))
		if d == nil || d.Request == nil || d.Request.UserInformation != nil {
			t.Errorf("dialogue %s, want nil user information", jsonText(normDialogue(d)))
		}
	})
	t.Run("present empty", func(t *testing.T) {
		const input = "62394804010203046b20281e060700118605010101a013601180020780a109060704000001001403be006c0fa10d02010102012d30050403010203"
		msg := mustParse(t, input)
		d := messageDialogue(msg)
		if d == nil || d.Request == nil || d.Request.UserInformation == nil || len(d.Request.UserInformation) != 0 {
			t.Fatalf("dialogue %s, want non-nil empty user information", jsonText(normDialogue(d)))
		}
		if out := hex.EncodeToString(mustMarshal(t, msg)); out != input {
			t.Errorf("Marshal:\n got %s\nwant %s", out, input)
		}
	})
	t.Run("two elements in order", func(t *testing.T) {
		const input = "62444804010203046b3c283a060700118605010101a02f602d80020780a109060704000001001403be1c280f060704000001010101a004a4028000280906032a030481020102"
		msg := mustParse(t, input)
		d := messageDialogue(msg)
		if d == nil || d.Request == nil {
			t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
		}
		want := []tcap.External{mapUserAbortExt(), {DirectReference: "1.2.3.4", Encoding: runtime.ExternalOctetAligned, OctetAligned: hx("0102")}}
		got, w := canonicalJSON(t, normUserInformation(d.Request.UserInformation)), canonicalJSON(t, normUserInformation(want))
		if !reflect.DeepEqual(got, w) {
			t.Errorf("user information:\n got %s\nwant %s", jsonText(got), jsonText(w))
		}
		if out := hex.EncodeToString(mustMarshal(t, msg)); out != input {
			t.Errorf("Marshal:\n got %s\nwant %s", out, input)
		}
	})
	// The provider ABRT rule of Q.774 clause 3.2.2.1 is a sender rule only.
	for _, c := range []struct{ name, input string }{
		{"provider ABRT with user information", "672d4904050607086b252823060700118605010101a0186416800101be11280f060704000001010101a004a4028000"},
		{"provider ABRT with empty user information", "671c4904050607086b142812060700118605010101a0076405800101be00"},
	} {
		t.Run(c.name, func(t *testing.T) {
			msg := mustParse(t, c.input)
			d := messageDialogue(msg)
			if d == nil || d.Abort == nil || d.Abort.UserInformation == nil {
				t.Fatalf("dialogue %s", jsonText(normDialogue(d)))
			}
			if v, ok := d.Abort.AbortSource.AsInt64(); !ok || v != 1 {
				t.Errorf("abort source %v, want dialogue-service-provider (1)", d.Abort.AbortSource.BigInt())
			}
			if _, err := msg.Marshal(); !errors.Is(err, tcap.ErrUnexpectedUserInformation) {
				t.Errorf("Marshal error = %v, want ErrUnexpectedUserInformation", err)
			}
		})
	}
}

// TestParseSingleASN1TypeNestedElement: a single-ASN1-type value is checked
// as well-formed BER throughout, not only as one outer element. A universal
// SEQUENCE holds complete encodings (ITU-T X.690 (02/2021) clause 8.9.2), so
// 30 04 30 30 30 30, whose inner element announces 48 octets, is refused in
// both modes, in user information and in an Opaque dialogue portion. With
// 30 04 30 02 05 00 the same messages parse and encode unchanged.
func TestParseSingleASN1TypeNestedElement(t *testing.T) {
	inputs := func(value string) []struct{ name, input string } {
		return []struct{ name, input string }{
			{"user information", tlv("62", hexOTID, dialoguePortion(hexDialogueAS, tlv("60", hexPV1, hexACN3, tlv("be", tlv("28", "060704000001010101", tlv("a0", value))))), tlv("6c", hexInvoke))},
			{"Opaque", tlv("64", hexDTID, tlv("6b", tlv("28", "06032a0304", tlv("a0", value))))},
		}
	}
	for _, c := range inputs("300430020500") {
		if out := hex.EncodeToString(mustMarshal(t, mustParse(t, c.input))); out != c.input {
			t.Fatalf("%s: Marshal:\n got %s\nwant %s", c.name, out, c.input)
		}
	}
	for _, c := range inputs("300430303030") {
		for _, tolerant := range []bool{false, true} {
			var opts []tcap.ParseOption
			if tolerant {
				opts = append(opts, tcap.WithTolerance(&ber.ViolationLog{}))
			}
			m, err := tcap.Parse(hx(c.input), opts...)
			var pe *tcap.ParseError
			if m != nil || !errors.Is(err, ber.ErrTruncated) || !errors.As(err, &pe) || pe.Portion != tcap.PortionDialogue {
				t.Fatalf("%s, tolerant %t: %v, %v", c.name, tolerant, m, err)
			}
		}
	}
}

// TestParseReceiverComponentRules covers the component rules of contract 4.2.
func TestParseReceiverComponentRules(t *testing.T) {
	cases := []struct {
		name, input string
		want        parseErrWant
	}{
		// X.880 InvokeId absent (NULL) is for a Reject only (Q.773 Table 18).
		{"invoke with NULL invoke ID", "62164804010203046c0ea10c050002012d30050403010203", parseErrWant{
			portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
			otid: "01020304", dtid: unchecked, compIndex: idx0, invokeID: "", constraint: true, noComponents: true,
		}},
		{"return result with NULL invoke ID", "640c4904050607086c04a2020500", parseErrWant{
			portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeEnd},
			otid: unchecked, dtid: "05060708", compIndex: idx0, invokeID: "", constraint: true,
		}},
		{"return error with NULL invoke ID", "640f4904050607086c07a3050500020101", parseErrWant{
			portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeEnd},
			otid: unchecked, dtid: "05060708", compIndex: idx0, invokeID: "", constraint: true,
		}},
		// 2^63 does not fit a LocalCode (int64).
		{"local operation code 2^63", "62184804010203046c10a10e0201010209008000000000000000", parseErrWant{
			portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
			otid: "01020304", dtid: unchecked, compIndex: idx0, invokeID: "1", is: tcap.ErrUnrepresentableValue,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := tcap.Parse(hx(c.input))
			checkParseError(t, err, c.want)
		})
	}
	t.Run("local operation code limits", func(t *testing.T) {
		for _, s := range []string{
			"62174804010203046c0fa10d02010102087fffffffffffffff",
			"62174804010203046c0fa10d02010102088000000000000000",
		} {
			msg := mustParse(t, s)
			if out := hex.EncodeToString(mustMarshal(t, msg)); out != s {
				t.Errorf("Marshal:\n got %s\nwant %s", out, s)
			}
		}
	})
}

func TestParseEmptyData(t *testing.T) {
	for _, data := range [][]byte{nil, {}} {
		msg, err := tcap.Parse(data)
		if msg != nil {
			t.Errorf("Parse(%x) returned a message", data)
		}
		checkParseError(t, err, parseErrWant{
			portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{""},
			otid: "", dtid: "", invokeID: "", is: tcap.ErrEmptyData,
		})
	}
}

func TestParseDecodeLimits(t *testing.T) {
	// Zero fields keep the defaults of ber.DefaultDecodeLimits (parse.go).
	msg, err := tcap.Parse(hx(corpusHex(t, "begin-aarq-map-open")), tcap.WithDecodeLimits(ber.DecodeLimits{}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertSameMessage(t, msg, mustParse(t, corpusHex(t, "begin-aarq-map-open")))
	if _, err := tcap.Parse(hx(corpusHex(t, "begin-aarq-map-open")), tcap.WithDecodeLimits(ber.DefaultDecodeLimits())); err != nil {
		t.Errorf("Parse with default limits: %v", err)
	}
}

// TestParseDoesNotAlias: "The returned message does not alias data"
// (parse.go); nor does a ParseError (errors.go).
func TestParseDoesNotAlias(t *testing.T) {
	inputs := []string{
		corpusHex(t, "begin-aarq-map-open"),
		corpusHex(t, "abort-abrt-user-map-userabort"),
		corpusHex(t, "continue-first-backward-aare-result"),
		corpusHex(t, "end-error-global"),
		"641c4904010203046b14281206032a030402010507036162638103010203",
		"64134904010203046b0b280906032a0304820204f0",
		"62374804010203046b1e281c0607001186050101018111600f80020780a1090607040000010014036c0fa10d02010102012d30050403010203",
		"62184804010203046c10a10e02010102012d3081050403010203",
	}
	for _, s := range inputs {
		data := hx(s)
		msg, err := tcap.Parse(data, tcap.WithTolerance(&ber.ViolationLog{}))
		if err != nil {
			t.Fatalf("Parse %s: %v", s, err)
		}
		before := jsonText(normalize(msg))
		for i := range data {
			data[i] ^= 0xff
		}
		if after := jsonText(normalize(msg)); after != before {
			t.Errorf("message changed with its input %s:\nbefore %s\n after %s", s, before, after)
		}
	}

	data := hx(parseErrorContinueHex)
	_, err := tcap.Parse(data, tcap.WithTolerance(&ber.ViolationLog{}))
	var pe *tcap.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("Parse error %v, want *tcap.ParseError", err)
	}
	before := jsonText([]any{pe.OTID.String(), pe.DTID.String(), normDialogue(pe.Dialogue), normComponents(pe.Components)})
	for i := range data {
		data[i] ^= 0xff
	}
	if after := jsonText([]any{pe.OTID.String(), pe.DTID.String(), normDialogue(pe.Dialogue), normComponents(pe.Components)}); after != before {
		t.Errorf("ParseError changed with its input:\nbefore %s\n after %s", before, after)
	}
}

// TestMarshalDoesNotAliasOrMutate: "The result never aliases the message"
// (message.go) and Marshal never mutates the message (contract section 3).
func TestMarshalDoesNotAliasOrMutate(t *testing.T) {
	build := func() []tcap.Message {
		return []tcap.Message{
			&tcap.Begin{OTID: tcap.TransactionID{1, 2, 3, 4}, Dialogue: aarqD(pv1(), acn3, []tcap.External{mapUserAbortExt()}), Components: []tcap.Component{invokeC(1)}},
			&tcap.End{DTID: tcap.TransactionID{1, 2, 3, 4}, Dialogue: &tcap.Dialogue{Opaque: opaqueE()}},
			&tcap.Continue{OTID: tcap.TransactionID{1}, DTID: tcap.TransactionID{2}, Components: []tcap.Component{
				{ReturnResultNotLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.GlobalCode("1.2.3"), Parameter: hx("0500")}}},
				{ReturnError: &tcap.ReturnError{InvokeID: 2, ErrorCode: tcap.LocalCode(7), Parameter: hx("0401ff")}},
			}},
			&tcap.Abort{DTID: tcap.TransactionID{9}, Dialogue: abrtUserD([]tcap.External{{DirectReference: "1.2", Encoding: runtime.ExternalArbitrary, Arbitrary: runtime.BitString{Bytes: hx("a0"), BitLength: 3}}})},
			&tcap.Unidirectional{Components: []tcap.Component{{Invoke: &tcap.Invoke{InvokeID: 5, LinkedID: ptr[int64](4), OpCode: tcap.LocalCode(1), Parameter: hx("3003020100")}}}},
			// Failing messages must not be changed either.
			&tcap.Begin{OTID: tcap.TransactionID{1, 2, 3, 4}, Components: []tcap.Component{invokeC(1), {Invoke: &tcap.Invoke{InvokeID: 2, OpCode: tcap.LocalCode(1), Parameter: hx("0401aa00")}}}},
			&tcap.Continue{OTID: tcap.TransactionID{1}, DTID: tcap.TransactionID{2}, Dialogue: aareD(pv("c0", 2), true)},
		}
	}
	for i, msg := range build() {
		before := jsonText(normalize(msg))
		out1, err1 := msg.Marshal()
		if after := jsonText(normalize(msg)); after != before {
			t.Errorf("message %d changed by Marshal:\nbefore %s\n after %s", i, before, after)
		}
		if err1 != nil {
			if i < 5 {
				t.Errorf("message %d: Marshal: %v", i, err1)
			}
			continue
		}
		keep := bytes.Clone(out1)
		for j := range out1 {
			out1[j] ^= 0xff
		}
		if after := jsonText(normalize(msg)); after != before {
			t.Errorf("message %d changed with the Marshal output:\nbefore %s\n after %s", i, before, after)
		}
		out2, err := msg.Marshal()
		if err != nil || !bytes.Equal(out2, keep) {
			t.Errorf("message %d: second Marshal = %x, %v; want %x", i, out2, err, keep)
		}
		// Changing the message afterwards does not change the output.
		mutateMessage(msg)
		if !bytes.Equal(out2, keep) {
			t.Errorf("message %d: Marshal output aliases the message", i)
		}
	}
}

// mutateMessage overwrites every byte slice reachable from msg.
func mutateMessage(msg tcap.Message) {
	flip := func(b []byte) {
		for i := range b {
			b[i] ^= 0xff
		}
	}
	ext := func(es []tcap.External) {
		for _, e := range es {
			flip(e.SingleASN1Type)
			flip(e.OctetAligned)
			flip(e.Arbitrary.Bytes)
		}
	}
	var comps []tcap.Component
	var d *tcap.Dialogue
	switch m := msg.(type) {
	case *tcap.Begin:
		flip(m.OTID)
		comps, d = m.Components, m.Dialogue
	case *tcap.Continue:
		flip(m.OTID)
		flip(m.DTID)
		comps, d = m.Components, m.Dialogue
	case *tcap.End:
		flip(m.DTID)
		comps, d = m.Components, m.Dialogue
	case *tcap.Abort:
		flip(m.DTID)
		d = m.Dialogue
	case *tcap.Unidirectional:
		comps, d = m.Components, m.Dialogue
	}
	for _, c := range comps {
		switch {
		case c.Invoke != nil:
			flip(c.Invoke.Parameter)
		case c.ReturnResultLast != nil && c.ReturnResultLast.Result != nil:
			flip(c.ReturnResultLast.Result.Parameter)
		case c.ReturnResultNotLast != nil && c.ReturnResultNotLast.Result != nil:
			flip(c.ReturnResultNotLast.Result.Parameter)
		case c.ReturnError != nil:
			flip(c.ReturnError.Parameter)
		}
	}
	if d == nil {
		return
	}
	switch {
	case d.Request != nil:
		if d.Request.ProtocolVersion != nil {
			flip(d.Request.ProtocolVersion.Bytes)
		}
		ext(d.Request.UserInformation)
	case d.Response != nil:
		if d.Response.ProtocolVersion != nil {
			flip(d.Response.ProtocolVersion.Bytes)
		}
		ext(d.Response.UserInformation)
	case d.Abort != nil:
		ext(d.Abort.UserInformation)
	case d.Unidirectional != nil:
		ext(d.Unidirectional.UserInformation)
	case d.Opaque != nil:
		ext([]tcap.External{*d.Opaque})
	}
}

// TestParseClearsUnusedBits covers BIT STRING values whose unused bits are
// set. ITU-T X.690 (02/2021) clause 8.6.2.2: the unused bits are not part of
// the value, so the parsed value has them cleared and marshals in the
// canonical form.
func TestParseClearsUnusedBits(t *testing.T) {
	// Continue with an AARE whose protocol-version is '1'B sent as 07 81.
	aare := "6538480405060708490401020304" + "6b2a2828060700118605010101a01d611b80020781a109060704000001001403a203020100a305a103020100"
	m := mustParse(t, aare)
	r := m.(*tcap.Continue).Dialogue.Response
	if got := r.ProtocolVersion; got == nil || got.BitLength != 1 || !bytes.Equal(got.Bytes, []byte{0x80}) {
		t.Fatalf("protocol-version %+v, want 80/1", got)
	}
	out, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := "65384804050607084904010203046b2a2828060700118605010101a01d611b80020780a109060704000001001403a203020100a305a103020100"; hex.EncodeToString(out) != want {
		t.Fatalf("Marshal %x, want %s", out, want)
	}

	// End with an opaque dialogue portion: EXTERNAL arbitrary [2] with four
	// unused bits, one of them set (found by FuzzParse).
	m = mustParse(t, "64134904303030306b0b2809060330303082020431")
	o := m.(*tcap.End).Dialogue.Opaque
	if o.Encoding != runtime.ExternalArbitrary || o.Arbitrary.BitLength != 4 || !bytes.Equal(o.Arbitrary.Bytes, []byte{0x30}) {
		t.Fatalf("arbitrary %+v, want 30/4", o.Arbitrary)
	}
	out, err = m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := "64134904303030306b0b2809060330303082020430"; hex.EncodeToString(out) != want {
		t.Fatalf("Marshal %x, want %s", out, want)
	}
}
