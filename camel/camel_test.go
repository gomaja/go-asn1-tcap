package camel_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1-tcap"
	"github.com/gomaja/go-asn1-tcap/camel"
)

var dottedOID = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))+$`)

type oidCase struct {
	name  string
	value tcap.OID
}

type codeCase struct {
	name  string
	value tcap.LocalCode
}

var oids = []oidCase{
	{"GsmSSFToGsmSCFContextV1", camel.GsmSSFToGsmSCFContextV1},
	{"GsmSSFToGsmSCFContextV2", camel.GsmSSFToGsmSCFContextV2},
	{"AssistGsmSSFToGsmSCFContextV2", camel.AssistGsmSSFToGsmSCFContextV2},
	{"GsmSRFToGsmSCFContextV2", camel.GsmSRFToGsmSCFContextV2},
	{"GsmSSFSCFGenericContextV3", camel.GsmSSFSCFGenericContextV3},
	{"GsmSSFSCFAssistHandoffContextV3", camel.GsmSSFSCFAssistHandoffContextV3},
	{"GsmSRFGsmSCFContextV3", camel.GsmSRFGsmSCFContextV3},
	{"GprsSSFGsmSCFContextV3", camel.GprsSSFGsmSCFContextV3},
	{"GsmSCFGprsSSFContextV3", camel.GsmSCFGprsSSFContextV3},
	{"SMSContextV3", camel.SMSContextV3},
	{"GsmSSFSCFGenericContextV4", camel.GsmSSFSCFGenericContextV4},
	{"GsmSSFSCFAssistHandoffContextV4", camel.GsmSSFSCFAssistHandoffContextV4},
	{"SCFGsmSSFGenericContextV4", camel.SCFGsmSSFGenericContextV4},
	{"GsmSRFGsmSCFContextV4", camel.GsmSRFGsmSCFContextV4},
	{"SMSContextV4", camel.SMSContextV4},
	{"UAbortReasonAS", camel.UAbortReasonAS},
	{"GPRSReferenceNumberAS", camel.GPRSReferenceNumberAS},
}

var operationCodes = []codeCase{
	{"OpCodeInitialDP", camel.OpCodeInitialDP},
	{"OpCodeAssistRequestInstructions", camel.OpCodeAssistRequestInstructions},
	{"OpCodeEstablishTemporaryConnection", camel.OpCodeEstablishTemporaryConnection},
	{"OpCodeDisconnectForwardConnection", camel.OpCodeDisconnectForwardConnection},
	{"OpCodeConnectToResource", camel.OpCodeConnectToResource},
	{"OpCodeConnect", camel.OpCodeConnect},
	{"OpCodeReleaseCall", camel.OpCodeReleaseCall},
	{"OpCodeRequestReportBCSMEvent", camel.OpCodeRequestReportBCSMEvent},
	{"OpCodeEventReportBCSM", camel.OpCodeEventReportBCSM},
	{"OpCodeCollectInformation", camel.OpCodeCollectInformation},
	{"OpCodeContinue", camel.OpCodeContinue},
	{"OpCodeInitiateCallAttempt", camel.OpCodeInitiateCallAttempt},
	{"OpCodeResetTimer", camel.OpCodeResetTimer},
	{"OpCodeFurnishChargingInformation", camel.OpCodeFurnishChargingInformation},
	{"OpCodeApplyCharging", camel.OpCodeApplyCharging},
	{"OpCodeApplyChargingReport", camel.OpCodeApplyChargingReport},
	{"OpCodeCallGap", camel.OpCodeCallGap},
	{"OpCodeCallInformationReport", camel.OpCodeCallInformationReport},
	{"OpCodeCallInformationRequest", camel.OpCodeCallInformationRequest},
	{"OpCodeSendChargingInformation", camel.OpCodeSendChargingInformation},
	{"OpCodePlayAnnouncement", camel.OpCodePlayAnnouncement},
	{"OpCodePromptAndCollectUserInformation", camel.OpCodePromptAndCollectUserInformation},
	{"OpCodeSpecializedResourceReport", camel.OpCodeSpecializedResourceReport},
	{"OpCodeCancel", camel.OpCodeCancel},
	{"OpCodeActivityTest", camel.OpCodeActivityTest},
	{"OpCodeInitialDPSMS", camel.OpCodeInitialDPSMS},
	{"OpCodeFurnishChargingInformationSMS", camel.OpCodeFurnishChargingInformationSMS},
	{"OpCodeConnectSMS", camel.OpCodeConnectSMS},
	{"OpCodeRequestReportSMSEvent", camel.OpCodeRequestReportSMSEvent},
	{"OpCodeEventReportSMS", camel.OpCodeEventReportSMS},
	{"OpCodeContinueSMS", camel.OpCodeContinueSMS},
	{"OpCodeReleaseSMS", camel.OpCodeReleaseSMS},
	{"OpCodeResetTimerSMS", camel.OpCodeResetTimerSMS},
	{"OpCodeActivityTestGPRS", camel.OpCodeActivityTestGPRS},
	{"OpCodeApplyChargingGPRS", camel.OpCodeApplyChargingGPRS},
	{"OpCodeApplyChargingReportGPRS", camel.OpCodeApplyChargingReportGPRS},
	{"OpCodeCancelGPRS", camel.OpCodeCancelGPRS},
	{"OpCodeConnectGPRS", camel.OpCodeConnectGPRS},
	{"OpCodeContinueGPRS", camel.OpCodeContinueGPRS},
	{"OpCodeEntityReleasedGPRS", camel.OpCodeEntityReleasedGPRS},
	{"OpCodeFurnishChargingInformationGPRS", camel.OpCodeFurnishChargingInformationGPRS},
	{"OpCodeInitialDPGPRS", camel.OpCodeInitialDPGPRS},
	{"OpCodeReleaseGPRS", camel.OpCodeReleaseGPRS},
	{"OpCodeEventReportGPRS", camel.OpCodeEventReportGPRS},
	{"OpCodeRequestReportGPRSEvent", camel.OpCodeRequestReportGPRSEvent},
	{"OpCodeResetTimerGPRS", camel.OpCodeResetTimerGPRS},
	{"OpCodeSendChargingInformationGPRS", camel.OpCodeSendChargingInformationGPRS},
	{"OpCodeDFCWithArgument", camel.OpCodeDFCWithArgument},
	{"OpCodeContinueWithArgument", camel.OpCodeContinueWithArgument},
	{"OpCodeDisconnectLeg", camel.OpCodeDisconnectLeg},
	{"OpCodeMoveLeg", camel.OpCodeMoveLeg},
	{"OpCodeSplitLeg", camel.OpCodeSplitLeg},
	{"OpCodeEntityReleased", camel.OpCodeEntityReleased},
	{"OpCodePlayTone", camel.OpCodePlayTone},
}

var errorCodes = []codeCase{
	{"ErrorCodeCanceled", camel.ErrorCodeCanceled},
	{"ErrorCodeCancelFailed", camel.ErrorCodeCancelFailed},
	{"ErrorCodeETCFailed", camel.ErrorCodeETCFailed},
	{"ErrorCodeImproperCallerResponse", camel.ErrorCodeImproperCallerResponse},
	{"ErrorCodeMissingCustomerRecord", camel.ErrorCodeMissingCustomerRecord},
	{"ErrorCodeMissingParameter", camel.ErrorCodeMissingParameter},
	{"ErrorCodeParameterOutOfRange", camel.ErrorCodeParameterOutOfRange},
	{"ErrorCodeRequestedInfoError", camel.ErrorCodeRequestedInfoError},
	{"ErrorCodeSystemFailure", camel.ErrorCodeSystemFailure},
	{"ErrorCodeTaskRefused", camel.ErrorCodeTaskRefused},
	{"ErrorCodeUnavailableResource", camel.ErrorCodeUnavailableResource},
	{"ErrorCodeUnexpectedComponentSequence", camel.ErrorCodeUnexpectedComponentSequence},
	{"ErrorCodeUnexpectedDataValue", camel.ErrorCodeUnexpectedDataValue},
	{"ErrorCodeUnexpectedParameter", camel.ErrorCodeUnexpectedParameter},
	{"ErrorCodeUnknownLegID", camel.ErrorCodeUnknownLegID},
	{"ErrorCodeUnknownPDPID", camel.ErrorCodeUnknownPDPID},
	{"ErrorCodeUnknownCSID", camel.ErrorCodeUnknownCSID},
}

// encodeOID returns the BER encoding (tag, length, contents) of a dotted
// object identifier, ITU-T X.690 (02/2021) clause 8.19.
func encodeOID(t *testing.T, s string) []byte {
	t.Helper()
	parts := strings.Split(s, ".")
	arcs := make([]uint64, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			t.Fatalf("OID %q: %v", s, err)
		}
		arcs[i] = v
	}
	sub := []uint64{arcs[0]*40 + arcs[1]}
	sub = append(sub, arcs[2:]...)
	var content []byte
	for _, v := range sub {
		var enc []byte
		enc = append(enc, byte(v&0x7f))
		for v >>= 7; v > 0; v >>= 7 {
			enc = append([]byte{byte(v&0x7f) | 0x80}, enc...)
		}
		content = append(content, enc...)
	}
	if len(content) > 127 {
		t.Fatalf("OID %q: contents too long for this helper", s)
	}
	return append([]byte{0x06, byte(len(content))}, content...)
}

func checkCanonical(t *testing.T, name, s string) {
	t.Helper()
	if !dottedOID.MatchString(s) {
		t.Errorf("%s = %q: not dotted decimal without leading zeros", name, s)
		return
	}
	arcs := strings.Split(s, ".")
	first, err := strconv.ParseUint(arcs[0], 10, 64)
	if err != nil || first > 2 {
		t.Errorf("%s = %q: first arc must be 0, 1 or 2", name, s)
		return
	}
	second, err := strconv.ParseUint(arcs[1], 10, 64)
	if err != nil {
		t.Errorf("%s = %q: second arc: %v", name, s, err)
		return
	}
	if first < 2 && second > 39 {
		t.Errorf("%s = %q: second arc exceeds 39 below first arc %d", name, s, first)
	}
}

func TestOIDsCanonicalAndUnique(t *testing.T) {
	seen := map[tcap.OID]string{}
	for _, c := range oids {
		checkCanonical(t, c.name, string(c.value))
		if prev, dup := seen[c.value]; dup {
			t.Errorf("%s and %s share the value %q", prev, c.name, c.value)
		}
		seen[c.value] = c.name
	}
	if len(oids) != 17 {
		t.Errorf("table has %d OIDs, want 17", len(oids))
	}
}

func TestCodesUnique(t *testing.T) {
	for kind, cases := range map[string][]codeCase{"operation": operationCodes, "error": errorCodes} {
		seen := map[tcap.LocalCode]string{}
		for _, c := range cases {
			if prev, dup := seen[c.value]; dup {
				t.Errorf("%s codes %s and %s share the value %d", kind, prev, c.name, c.value)
			}
			seen[c.value] = c.name
		}
	}
	if len(operationCodes) != 54 || len(errorCodes) != 17 {
		t.Errorf("tables have %d operation and %d error codes, want 54 and 17", len(operationCodes), len(errorCodes))
	}
}

func TestEncodeOID(t *testing.T) {
	got := encodeOID(t, "0.4.0.0.1.0.50.1")
	want := []byte{0x06, 0x07, 0x04, 0x00, 0x00, 0x01, 0x00, 0x32, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeOID = %x, want %x", got, want)
	}
}

// TestV2ContextInCapture checks the version 2 context against the real
// capture "Camel-V2 invoke initialDP (CapGsmssfToGsmscfContext)".
func TestV2ContextInCapture(t *testing.T) {
	data, err := os.ReadFile("../testdata/captures.json")
	if err != nil {
		t.Fatal(err)
	}
	var captures []struct {
		Name string `json:"name"`
		Hex  string `json:"hex"`
	}
	if err := json.Unmarshal(data, &captures); err != nil {
		t.Fatal(err)
	}
	const name = "Camel-V2 invoke initialDP (CapGsmssfToGsmscfContext)"
	for _, c := range captures {
		if c.Name != name {
			continue
		}
		raw, err := hex.DecodeString(c.Hex)
		if err != nil {
			t.Fatal(err)
		}
		enc := encodeOID(t, string(camel.GsmSSFToGsmSCFContextV2))
		if !bytes.Equal(enc, []byte{0x06, 0x07, 0x04, 0x00, 0x00, 0x01, 0x00, 0x32, 0x01}) {
			t.Fatalf("encoded context = %x", enc)
		}
		if !bytes.Contains(raw, enc) {
			t.Errorf("capture %q does not contain the encoding %x of GsmSSFToGsmSCFContextV2", name, enc)
		}
		return
	}
	t.Fatalf("capture %q not found", name)
}

// TestTablesCoverPackage checks that the tables list every constant the
// package declares and that the package declares constants only.
func TestTablesCoverPackage(t *testing.T) {
	fset := token.NewFileSet()
	declared := map[string]bool{}
	for _, f := range []string{"acn.go", "userinfo.go", "opcode.go", "errcode.go"} {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST && gd.Tok != token.IMPORT {
				t.Errorf("%s: package must hold constants only", f)
				continue
			}
			if gd.Tok == token.IMPORT {
				continue
			}
			for _, s := range gd.Specs {
				for _, n := range s.(*ast.ValueSpec).Names {
					declared[n.Name] = true
				}
			}
		}
	}
	listed := map[string]bool{}
	for _, c := range oids {
		listed[c.name] = true
	}
	for _, c := range operationCodes {
		listed[c.name] = true
	}
	for _, c := range errorCodes {
		listed[c.name] = true
	}
	for n := range declared {
		if !listed[n] {
			t.Errorf("constant %s is not covered by the tables", n)
		}
	}
	for n := range listed {
		if !declared[n] {
			t.Errorf("table entry %s is not declared in the package", n)
		}
	}
}
