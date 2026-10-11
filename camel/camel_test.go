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
	want  tcap.OID // from the specification text, independently of the package
}

type codeCase struct {
	name  string
	value tcap.LocalCode
	want  tcap.LocalCode // from the specification text, independently of the package
}

var oids = []oidCase{
	{"GsmSSFToGsmSCFContextV1", camel.GsmSSFToGsmSCFContextV1, "0.4.0.0.1.0.50.0"},
	{"GsmSSFToGsmSCFContextV2", camel.GsmSSFToGsmSCFContextV2, "0.4.0.0.1.0.50.1"},
	{"AssistGsmSSFToGsmSCFContextV2", camel.AssistGsmSSFToGsmSCFContextV2, "0.4.0.0.1.0.51.1"},
	{"GsmSRFToGsmSCFContextV2", camel.GsmSRFToGsmSCFContextV2, "0.4.0.0.1.0.52.1"},
	{"GsmSSFSCFGenericContextV3", camel.GsmSSFSCFGenericContextV3, "0.4.0.0.1.21.3.4"},
	{"GsmSSFSCFAssistHandoffContextV3", camel.GsmSSFSCFAssistHandoffContextV3, "0.4.0.0.1.21.3.6"},
	{"GsmSRFGsmSCFContextV3", camel.GsmSRFGsmSCFContextV3, "0.4.0.0.1.20.3.14"},
	{"GprsSSFGsmSCFContextV3", camel.GprsSSFGsmSCFContextV3, "0.4.0.0.1.21.3.50"},
	{"GsmSCFGprsSSFContextV3", camel.GsmSCFGprsSSFContextV3, "0.4.0.0.1.21.3.51"},
	{"SMSContextV3", camel.SMSContextV3, "0.4.0.0.1.21.3.61"},
	{"GsmSSFSCFGenericContextV4", camel.GsmSSFSCFGenericContextV4, "0.4.0.0.1.23.3.4"},
	{"GsmSSFSCFAssistHandoffContextV4", camel.GsmSSFSCFAssistHandoffContextV4, "0.4.0.0.1.23.3.6"},
	{"SCFGsmSSFGenericContextV4", camel.SCFGsmSSFGenericContextV4, "0.4.0.0.1.23.3.8"},
	{"GsmSRFGsmSCFContextV4", camel.GsmSRFGsmSCFContextV4, "0.4.0.0.1.22.3.14"},
	{"SMSContextV4", camel.SMSContextV4, "0.4.0.0.1.23.3.61"},
	{"UAbortReasonAS", camel.UAbortReasonAS, "0.4.0.0.1.1.2.2"},
	{"GPRSReferenceNumberAS", camel.GPRSReferenceNumberAS, "0.4.0.0.1.1.5.2"},
}

var operationCodes = []codeCase{
	{"OpCodeInitialDP", camel.OpCodeInitialDP, 0},
	{"OpCodeAssistRequestInstructions", camel.OpCodeAssistRequestInstructions, 16},
	{"OpCodeEstablishTemporaryConnection", camel.OpCodeEstablishTemporaryConnection, 17},
	{"OpCodeDisconnectForwardConnection", camel.OpCodeDisconnectForwardConnection, 18},
	{"OpCodeConnectToResource", camel.OpCodeConnectToResource, 19},
	{"OpCodeConnect", camel.OpCodeConnect, 20},
	{"OpCodeReleaseCall", camel.OpCodeReleaseCall, 22},
	{"OpCodeRequestReportBCSMEvent", camel.OpCodeRequestReportBCSMEvent, 23},
	{"OpCodeEventReportBCSM", camel.OpCodeEventReportBCSM, 24},
	{"OpCodeCollectInformation", camel.OpCodeCollectInformation, 27},
	{"OpCodeContinue", camel.OpCodeContinue, 31},
	{"OpCodeInitiateCallAttempt", camel.OpCodeInitiateCallAttempt, 32},
	{"OpCodeResetTimer", camel.OpCodeResetTimer, 33},
	{"OpCodeFurnishChargingInformation", camel.OpCodeFurnishChargingInformation, 34},
	{"OpCodeApplyCharging", camel.OpCodeApplyCharging, 35},
	{"OpCodeApplyChargingReport", camel.OpCodeApplyChargingReport, 36},
	{"OpCodeCallGap", camel.OpCodeCallGap, 41},
	{"OpCodeCallInformationReport", camel.OpCodeCallInformationReport, 44},
	{"OpCodeCallInformationRequest", camel.OpCodeCallInformationRequest, 45},
	{"OpCodeSendChargingInformation", camel.OpCodeSendChargingInformation, 46},
	{"OpCodePlayAnnouncement", camel.OpCodePlayAnnouncement, 47},
	{"OpCodePromptAndCollectUserInformation", camel.OpCodePromptAndCollectUserInformation, 48},
	{"OpCodeSpecializedResourceReport", camel.OpCodeSpecializedResourceReport, 49},
	{"OpCodeCancel", camel.OpCodeCancel, 53},
	{"OpCodeActivityTest", camel.OpCodeActivityTest, 55},
	{"OpCodeInitialDPSMS", camel.OpCodeInitialDPSMS, 60},
	{"OpCodeFurnishChargingInformationSMS", camel.OpCodeFurnishChargingInformationSMS, 61},
	{"OpCodeConnectSMS", camel.OpCodeConnectSMS, 62},
	{"OpCodeRequestReportSMSEvent", camel.OpCodeRequestReportSMSEvent, 63},
	{"OpCodeEventReportSMS", camel.OpCodeEventReportSMS, 64},
	{"OpCodeContinueSMS", camel.OpCodeContinueSMS, 65},
	{"OpCodeReleaseSMS", camel.OpCodeReleaseSMS, 66},
	{"OpCodeResetTimerSMS", camel.OpCodeResetTimerSMS, 67},
	{"OpCodeActivityTestGPRS", camel.OpCodeActivityTestGPRS, 70},
	{"OpCodeApplyChargingGPRS", camel.OpCodeApplyChargingGPRS, 71},
	{"OpCodeApplyChargingReportGPRS", camel.OpCodeApplyChargingReportGPRS, 72},
	{"OpCodeCancelGPRS", camel.OpCodeCancelGPRS, 73},
	{"OpCodeConnectGPRS", camel.OpCodeConnectGPRS, 74},
	{"OpCodeContinueGPRS", camel.OpCodeContinueGPRS, 75},
	{"OpCodeEntityReleasedGPRS", camel.OpCodeEntityReleasedGPRS, 76},
	{"OpCodeFurnishChargingInformationGPRS", camel.OpCodeFurnishChargingInformationGPRS, 77},
	{"OpCodeInitialDPGPRS", camel.OpCodeInitialDPGPRS, 78},
	{"OpCodeReleaseGPRS", camel.OpCodeReleaseGPRS, 79},
	{"OpCodeEventReportGPRS", camel.OpCodeEventReportGPRS, 80},
	{"OpCodeRequestReportGPRSEvent", camel.OpCodeRequestReportGPRSEvent, 81},
	{"OpCodeResetTimerGPRS", camel.OpCodeResetTimerGPRS, 82},
	{"OpCodeSendChargingInformationGPRS", camel.OpCodeSendChargingInformationGPRS, 83},
	{"OpCodeDFCWithArgument", camel.OpCodeDFCWithArgument, 86},
	{"OpCodeContinueWithArgument", camel.OpCodeContinueWithArgument, 88},
	{"OpCodeDisconnectLeg", camel.OpCodeDisconnectLeg, 90},
	{"OpCodeMoveLeg", camel.OpCodeMoveLeg, 93},
	{"OpCodeSplitLeg", camel.OpCodeSplitLeg, 95},
	{"OpCodeEntityReleased", camel.OpCodeEntityReleased, 96},
	{"OpCodePlayTone", camel.OpCodePlayTone, 97},
}

var errorCodes = []codeCase{
	{"ErrorCodeCanceled", camel.ErrorCodeCanceled, 0},
	{"ErrorCodeCancelFailed", camel.ErrorCodeCancelFailed, 1},
	{"ErrorCodeETCFailed", camel.ErrorCodeETCFailed, 3},
	{"ErrorCodeImproperCallerResponse", camel.ErrorCodeImproperCallerResponse, 4},
	{"ErrorCodeMissingCustomerRecord", camel.ErrorCodeMissingCustomerRecord, 6},
	{"ErrorCodeMissingParameter", camel.ErrorCodeMissingParameter, 7},
	{"ErrorCodeParameterOutOfRange", camel.ErrorCodeParameterOutOfRange, 8},
	{"ErrorCodeRequestedInfoError", camel.ErrorCodeRequestedInfoError, 10},
	{"ErrorCodeSystemFailure", camel.ErrorCodeSystemFailure, 11},
	{"ErrorCodeTaskRefused", camel.ErrorCodeTaskRefused, 12},
	{"ErrorCodeUnavailableResource", camel.ErrorCodeUnavailableResource, 13},
	{"ErrorCodeUnexpectedComponentSequence", camel.ErrorCodeUnexpectedComponentSequence, 14},
	{"ErrorCodeUnexpectedDataValue", camel.ErrorCodeUnexpectedDataValue, 15},
	{"ErrorCodeUnexpectedParameter", camel.ErrorCodeUnexpectedParameter, 16},
	{"ErrorCodeUnknownLegID", camel.ErrorCodeUnknownLegID, 17},
	{"ErrorCodeUnknownPDPID", camel.ErrorCodeUnknownPDPID, 50},
	{"ErrorCodeUnknownCSID", camel.ErrorCodeUnknownCSID, 51},
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

// TestValuesMatchSpecification compares every constant with the value read
// from 3GPP TS 29.078 V19.0.0 (clauses 5.3, 5.4, 5.6, 5.7 and 8.1.1), GSM 09.78
// version 5.6.0 clause 6.5 and version 7.1.0 clause 6.6, and TS 29.078 V4.9.0
// clause 5.6, so that an edited value cannot pass the uniqueness checks alone.
func TestValuesMatchSpecification(t *testing.T) {
	for _, c := range oids {
		if c.value != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.value, c.want)
		}
	}
	for _, cases := range [][]codeCase{operationCodes, errorCodes} {
		for _, c := range cases {
			if c.value != c.want {
				t.Errorf("%s = %d, want %d", c.name, c.value, c.want)
			}
		}
	}
}
