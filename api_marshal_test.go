package tcap_test

import (
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

var (
	tidO = tcap.TransactionID{0x01, 0x02, 0x03, 0x04}
	tidD = tcap.TransactionID{0x05, 0x06, 0x07, 0x08}
)

const acn3 = tcap.OID("0.4.0.0.1.0.20.3")

func pv(bytes string, bitLength int) *runtime.BitString {
	return &runtime.BitString{Bytes: hx(bytes), BitLength: bitLength}
}

func pv1() *runtime.BitString { return pv("80", 1) }

func invokeC(id int64) tcap.Component {
	return tcap.Component{Invoke: &tcap.Invoke{InvokeID: id, OpCode: tcap.LocalCode(45), Parameter: hx("30050403010203")}}
}

func userNull() *wire.AssociateSourceDiagnosticDialogueServiceUserValue {
	return ptr(wire.AssociateSourceDiagnosticDialogueServiceUserValueNullValue())
}

func aarqD(version *runtime.BitString, acn tcap.OID, ui []tcap.External) *tcap.Dialogue {
	return &tcap.Dialogue{Request: &tcap.AARQ{ProtocolVersion: version, ApplicationContextName: acn, UserInformation: ui}}
}

func aareD(version *runtime.BitString, accepted bool) *tcap.Dialogue {
	r := &tcap.AARE{
		ProtocolVersion:        version,
		ApplicationContextName: acn3,
		Result:                 wire.AssociateResultAcceptedValue(),
		ResultSourceDiagnostic: tcap.ResultSourceDiagnostic{DialogueServiceUser: userNull()},
	}
	if !accepted {
		r.Result = wire.AssociateResultRejectPermanentValue()
		r.ResultSourceDiagnostic = tcap.ResultSourceDiagnostic{
			DialogueServiceUser: ptr(wire.AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedValue()),
		}
	}
	return &tcap.Dialogue{Response: r}
}

func abrtUserD(ui []tcap.External) *tcap.Dialogue {
	return &tcap.Dialogue{Abort: &tcap.ABRT{AbortSource: wire.ABRTSourceDialogueServiceUserValue(), UserInformation: ui}}
}

func audtD(version *runtime.BitString, acn tcap.OID) *tcap.Dialogue {
	return &tcap.Dialogue{Unidirectional: &tcap.AUDT{ProtocolVersion: version, ApplicationContextName: acn}}
}

func opaqueE() *tcap.External {
	return &tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: hx("0402aabb")}
}

func mapUserAbortExt() tcap.External {
	return tcap.External{DirectReference: "0.4.0.0.1.1.1.1", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: hx("a4028000")}
}

func beginWith(c ...tcap.Component) *tcap.Begin { return &tcap.Begin{OTID: tidO, Components: c} }

func beginD(d *tcap.Dialogue) *tcap.Begin {
	return &tcap.Begin{OTID: tidO, Dialogue: d, Components: []tcap.Component{invokeC(1)}}
}

type marshalCase struct {
	name string
	msg  tcap.Message
	// want is the expected encoding; when empty, Marshal must fail.
	want string
	// is is a sentinel reachable with errors.Is.
	is error
	// constraint requires a *ber.ValidationError reachable with errors.As.
	constraint bool
	// constraintPath, when set, is the exact generated ValidationError path.
	constraintPath string
	// path, when set, is the exact *tcap.FieldError path; pathPrefix is a
	// prefix of it.
	path       string
	pathPrefix string
}

// fieldSentinels are the errors Marshal detects itself and reports inside a
// *tcap.FieldError (contract section 3).
var fieldSentinels = []error{
	tcap.ErrInvalidOID, tcap.ErrUnrepresentableValue,
	tcap.ErrComponentNoAlternative, tcap.ErrComponentMultipleAlternatives,
	tcap.ErrCodeNoAlternative, tcap.ErrProblemNoAlternative, tcap.ErrProblemMultipleAlternatives,
	tcap.ErrResultSourceDiagnosticNoAlternative, tcap.ErrResultSourceDiagnosticMultipleAlternatives,
	tcap.ErrDialogueNoAlternative, tcap.ErrDialogueMultipleAlternatives,
	tcap.ErrUnexpectedDialoguePDU, tcap.ErrUnexpectedDialogueResult, tcap.ErrUnexpectedUserInformation,
	tcap.ErrUnsupportedProtocolVersion, tcap.ErrAbortMultipleReasons,
	tcap.ErrExternalEncoding,
}

func isTCAPSentinel(err error) bool {
	for _, s := range fieldSentinels {
		if err == s {
			return true
		}
	}
	return false
}

func runMarshalCases(t *testing.T, cases []marshalCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := c.msg.Marshal()
			if c.want != "" {
				if err != nil {
					t.Fatalf("Marshal: %v", err)
				}
				if got := hex.EncodeToString(out); got != c.want {
					t.Fatalf("Marshal:\n got %s\nwant %s", got, c.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("Marshal succeeded with %x, want an error", out)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Errorf("errors.Is(%v, %v) = false", err, c.is)
			}
			if c.constraint {
				var ce *ber.ValidationError
				if !errors.As(err, &ce) {
					t.Errorf("error %v does not wrap *ber.ValidationError", err)
				} else if c.constraintPath != "" && ce.Path != c.constraintPath {
					t.Errorf("ValidationError.Path = %q, want %q", ce.Path, c.constraintPath)
				}
			}
			var fe *tcap.FieldError
			hasField := errors.As(err, &fe)
			if (c.path != "" || c.pathPrefix != "" || isTCAPSentinel(c.is)) && !hasField {
				t.Fatalf("error %v does not wrap *tcap.FieldError", err)
			}
			if hasField && fe.Error() == "" {
				t.Error("FieldError.Error() is empty")
			}
			if c.path != "" && fe.Path != c.path {
				t.Errorf("FieldError.Path = %q, want %q", fe.Path, c.path)
			}
			if c.pathPrefix != "" && !strings.HasPrefix(fe.Path, c.pathPrefix) {
				t.Errorf("FieldError.Path = %q, want prefix %q", fe.Path, c.pathPrefix)
			}
		})
	}
}

func TestMarshalNilReceivers(t *testing.T) {
	for _, msg := range []tcap.Message{(*tcap.Begin)(nil), (*tcap.Continue)(nil), (*tcap.End)(nil), (*tcap.Abort)(nil), (*tcap.Unidirectional)(nil)} {
		t.Run(string(messageTypeOf(msg)), func(t *testing.T) {
			out, err := msg.Marshal()
			if !errors.Is(err, tcap.ErrNilMessage) {
				t.Errorf("Marshal = %x, %v; want ErrNilMessage", out, err)
			}
		})
	}
}

// TestMarshalCorpusEquivalents builds the corpus values by hand and checks
// their exact encodings.
func TestMarshalCorpusEquivalents(t *testing.T) {
	c := func(id string) string { return corpusHex(t, id) }
	runMarshalCases(t, []marshalCase{
		{name: "begin-otid-1", msg: &tcap.Begin{OTID: tcap.TransactionID{1}, Components: []tcap.Component{invokeC(1)}}, want: c("begin-otid-1")},
		{name: "begin-otid-4", msg: beginWith(invokeC(1)), want: c("begin-otid-4")},
		{name: "begin-aarq-invoke", msg: beginD(aarqD(pv1(), acn3, nil)), want: c("begin-aarq-invoke")},
		{name: "begin-aarq-default-version", msg: beginD(aarqD(nil, acn3, nil)), want: c("begin-aarq-default-version")},
		{name: "begin-aarq-no-components", msg: &tcap.Begin{OTID: tidO, Dialogue: aarqD(pv1(), acn3, nil)}, want: c("begin-aarq-no-components")},
		{name: "begin-aarq-map-open", msg: &tcap.Begin{
			OTID: tidO,
			Dialogue: aarqD(pv1(), acn3, []tcap.External{{
				DirectReference: "0.4.0.0.1.1.1.1", Encoding: runtime.ExternalSingleASN1Type,
				SingleASN1Type: hx("a00e800591214365f7810591769810f2"),
			}}),
			Components: []tcap.Component{{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.LocalCode(45), Parameter: hx("3011800591214365f78101ff820591769810f2")}}},
		}, want: c("begin-aarq-map-open")},
		{name: "begin-global-opcode", msg: beginWith(tcap.Component{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.GlobalCode("1.2.3.4"), Parameter: hx("30050403010203")}}), want: c("begin-global-opcode")},
		{name: "begin-two-invokes", msg: beginWith(invokeC(1), tcap.Component{Invoke: &tcap.Invoke{InvokeID: 2, OpCode: tcap.LocalCode(60), Parameter: hx("30050403010203")}}), want: c("begin-two-invokes")},
		{name: "begin-argument-300-octets", msg: beginWith(tcap.Component{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.LocalCode(45), Parameter: hx(tlv("30", tlv("04", hex.EncodeToString(append(seq(256), seq(44)...)))))}}), want: c("begin-argument-300-octets")},
		{name: "continue-first-backward-aare-result", msg: &tcap.Continue{OTID: tidO, DTID: tidD, Dialogue: aareD(pv1(), true), Components: []tcap.Component{
			{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(45), Parameter: hx("30040402aabb")}}},
		}}, want: c("continue-first-backward-aare-result")},
		{name: "continue-result-not-last-then-last", msg: &tcap.Continue{OTID: tidO, DTID: tidD, Components: []tcap.Component{
			{ReturnResultNotLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(45), Parameter: hx("30040402aabb")}}},
			{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(45), Parameter: hx("30040402aabb")}}},
		}}, want: c("continue-result-not-last-then-last")},
		{name: "end-result-invokeid-only", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1}}}}, want: c("end-result-invokeid-only")},
		{name: "end-dtid-one-octet", msg: &tcap.End{DTID: tcap.TransactionID{5}, Components: []tcap.Component{{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1}}}}, want: c("end-dtid-one-octet")},
		{name: "end-error-local-parameter", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnError: &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.LocalCode(1), Parameter: hx("30030a0100")}}}}, want: c("end-error-local-parameter")},
		{name: "end-error-local-no-parameter", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnError: &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.LocalCode(1)}}}}, want: c("end-error-local-no-parameter")},
		{name: "end-error-global", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnError: &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.GlobalCode("1.2.3.4")}}}}, want: c("end-error-global")},
		{name: "end-reject-invoke", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{Reject: &tcap.Reject{InvokeID: ptr[int64](1), Problem: tcap.Problem{Invoke: ptr(wire.InvokeProblemUnrecognizedOperationValue())}}}}}, want: c("end-reject-invoke")},
		{name: "end-reject-null-general", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{Reject: &tcap.Reject{Problem: tcap.Problem{General: ptr(wire.GeneralProblemBadlyStructuredPDUValue())}}}}}, want: c("end-reject-null-general")},
		{name: "end-reject-return-result", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{Reject: &tcap.Reject{InvokeID: ptr[int64](1), Problem: tcap.Problem{ReturnResult: ptr(wire.NewReturnResultProblemInt64(2))}}}}}, want: c("end-reject-return-result")},
		{name: "end-reject-return-error", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{Reject: &tcap.Reject{InvokeID: ptr[int64](1), Problem: tcap.Problem{ReturnError: ptr(wire.NewReturnErrorProblemInt64(4))}}}}}, want: c("end-reject-return-error")},
		{name: "end-error-and-reject", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{
			{ReturnError: &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.LocalCode(1), Parameter: hx("30030a0100")}},
			{Reject: &tcap.Reject{InvokeID: ptr[int64](2), Problem: tcap.Problem{Invoke: ptr(wire.NewInvokeProblemInt64(1))}}},
		}}, want: c("end-error-and-reject")},
		{name: "end-aare-single-response", msg: &tcap.End{DTID: tidD, Dialogue: aareD(nil, true)}, want: c("end-aare-single-response")},
		{name: "abort-no-reason", msg: &tcap.Abort{DTID: tidD}, want: c("abort-no-reason")},
		{name: "abort-p-cause-0", msg: &tcap.Abort{DTID: tidD, PAbortCause: ptr(wire.PAbortCauseUnrecognizedMessageTypeValue())}, want: c("abort-p-cause-0")},
		{name: "abort-p-cause-4", msg: &tcap.Abort{DTID: tidD, PAbortCause: ptr(wire.PAbortCauseResourceLimitationValue())}, want: c("abort-p-cause-4")},
		{name: "abort-p-cause-127", msg: &tcap.Abort{DTID: tidD, PAbortCause: ptr(wire.NewPAbortCauseInt64(127))}, want: c("abort-p-cause-127")},
		{name: "abort-aare-map-version-fallback", msg: &tcap.Abort{DTID: tidD, Dialogue: &tcap.Dialogue{Response: &tcap.AARE{
			ProtocolVersion: pv1(), ApplicationContextName: "0.4.0.0.1.0.20.2", Result: wire.AssociateResultRejectPermanentValue(),
			ResultSourceDiagnostic: tcap.ResultSourceDiagnostic{DialogueServiceUser: ptr(wire.AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedValue())},
		}}}, want: c("abort-aare-map-version-fallback")},
		{name: "abort-aare-provider-no-common-dialogue", msg: &tcap.Abort{DTID: tidD, Dialogue: &tcap.Dialogue{Response: &tcap.AARE{
			ProtocolVersion: pv1(), ApplicationContextName: acn3, Result: wire.AssociateResultRejectPermanentValue(),
			ResultSourceDiagnostic: tcap.ResultSourceDiagnostic{DialogueServiceProvider: ptr(wire.AssociateSourceDiagnosticDialogueServiceProviderValueNoCommonDialoguePortionValue())},
		}}}, want: c("abort-aare-provider-no-common-dialogue")},
		{name: "abort-abrt-user-map-userabort", msg: &tcap.Abort{DTID: tidD, Dialogue: abrtUserD([]tcap.External{mapUserAbortExt()})}, want: c("abort-abrt-user-map-userabort")},
		{name: "abort-abrt-provider", msg: &tcap.Abort{DTID: tidD, Dialogue: &tcap.Dialogue{Abort: &tcap.ABRT{AbortSource: wire.ABRTSourceDialogueServiceProviderValue()}}}, want: c("abort-abrt-provider")},
		{name: "unidirectional-invoke-only", msg: &tcap.Unidirectional{Components: []tcap.Component{invokeC(1)}}, want: c("unidirectional-invoke-only")},
		{name: "unidirectional-audt-invoke", msg: &tcap.Unidirectional{Dialogue: audtD(pv1(), acn3), Components: []tcap.Component{invokeC(1)}}, want: c("unidirectional-audt-invoke")},
	})
}

// TestMarshalIssue13 is go-asn1-tcap issue #13: a linked ID is encoded as
// [0] IMPLICIT INTEGER (ITU-T Q.773 (06/97) Table 20), 80 01 01.
func TestMarshalIssue13(t *testing.T) {
	const want = "62134804010203046c0ba10902010380010102013c"
	msg := &tcap.Begin{OTID: tidO, Components: []tcap.Component{{Invoke: &tcap.Invoke{InvokeID: 3, LinkedID: ptr[int64](1), OpCode: tcap.LocalCode(60)}}}}
	out, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("Marshal:\n got %s\nwant %s", got, want)
	}
	parsed, err := tcap.Parse(hx(want))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertSameMessage(t, msg, parsed)
	b := parsed.(*tcap.Begin)
	if inv := b.Components[0].Invoke; inv == nil || inv.LinkedID == nil || *inv.LinkedID != 1 || inv.Parameter != nil {
		t.Errorf("parsed %s", jsonText(normalize(parsed)))
	}
}

// TestMarshalTransactionPortion: OTID and DTID are OCTET STRING (SIZE (1..4)),
// Q.773 clause 3.1; the codec reports the constraint (contract 3.1).
func TestMarshalTransactionPortion(t *testing.T) {
	five := tcap.TransactionID{1, 2, 3, 4, 5}
	runMarshalCases(t, []marshalCase{
		{name: "begin OTID nil", msg: &tcap.Begin{Components: []tcap.Component{invokeC(1)}}, constraint: true},
		{name: "begin OTID empty", msg: &tcap.Begin{OTID: tcap.TransactionID{}, Components: []tcap.Component{invokeC(1)}}, constraint: true},
		{name: "begin OTID 5 octets", msg: &tcap.Begin{OTID: five, Components: []tcap.Component{invokeC(1)}}, constraint: true},
		{name: "continue DTID nil", msg: &tcap.Continue{OTID: tidO, Components: []tcap.Component{invokeC(1)}}, constraint: true},
		{name: "continue OTID 5 octets", msg: &tcap.Continue{OTID: five, DTID: tidD, Components: []tcap.Component{invokeC(1)}}, constraint: true},
		{name: "end DTID 5 octets", msg: &tcap.End{DTID: five}, constraint: true},
		{name: "abort DTID empty", msg: &tcap.Abort{DTID: tcap.TransactionID{}}, constraint: true},
		{name: "end without portions", msg: &tcap.End{DTID: tidD}, want: tlv("64", hexDTID)},
		{name: "continue without portions", msg: &tcap.Continue{OTID: tidO, DTID: tidD}, want: tlv("65", hexOTID, hexDTID)},
	})
}

// TestMarshalComponentPortion covers contract 3.2 and 3.3.
func TestMarshalComponentPortion(t *testing.T) {
	runMarshalCases(t, []marshalCase{
		{name: "begin empty components", msg: &tcap.Begin{OTID: tidO, Components: []tcap.Component{}}, constraint: true},
		{name: "unidirectional empty components", msg: &tcap.Unidirectional{Components: []tcap.Component{}}, constraint: true},
		// The codec requires the component portion of a Unidirectional
		// (runtime error ber.ErrInvalidValue, "required collection is nil").
		{name: "unidirectional nil components", msg: &tcap.Unidirectional{}, is: ber.ErrInvalidValue},
		{name: "no alternative", msg: beginWith(tcap.Component{}), is: tcap.ErrComponentNoAlternative, pathPrefix: "Components[0]"},
		{name: "no alternative second", msg: beginWith(invokeC(1), tcap.Component{}), is: tcap.ErrComponentNoAlternative, pathPrefix: "Components[1]"},
		{name: "invoke and reject", msg: beginWith(tcap.Component{
			Invoke: invokeC(1).Invoke,
			Reject: &tcap.Reject{Problem: tcap.Problem{General: ptr(wire.GeneralProblemUnrecognizedPDUValue())}},
		}), is: tcap.ErrComponentMultipleAlternatives, pathPrefix: "Components[0]"},
		{name: "result last and not last", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{
			ReturnResultLast: &tcap.ReturnResult{InvokeID: 1}, ReturnResultNotLast: &tcap.ReturnResult{InvokeID: 1},
		}}}, is: tcap.ErrComponentMultipleAlternatives, pathPrefix: "Components[0]"},
		{name: "all five", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{
			Invoke: invokeC(1).Invoke, ReturnResultLast: &tcap.ReturnResult{InvokeID: 1}, ReturnResultNotLast: &tcap.ReturnResult{InvokeID: 1},
			ReturnError: &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.LocalCode(1)},
			Reject:      &tcap.Reject{Problem: tcap.Problem{General: ptr(wire.GeneralProblemUnrecognizedPDUValue())}},
		}}}, is: tcap.ErrComponentMultipleAlternatives},
	})
}

// TestMarshalComponentIDs: component IDs are one octet, -128..127 (Q.773
// clause 4.2.2.2), reported as *ber.ValidationError (contract 3.4).
func TestMarshalComponentIDs(t *testing.T) {
	linked := func(id int64) *tcap.Begin {
		return beginWith(tcap.Component{Invoke: &tcap.Invoke{InvokeID: 3, LinkedID: &id, OpCode: tcap.LocalCode(60)}})
	}
	rrl := func(id int64) *tcap.End {
		return &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnResultLast: &tcap.ReturnResult{InvokeID: id}}}}
	}
	rrnl := func(id int64) *tcap.Continue {
		return &tcap.Continue{OTID: tidO, DTID: tidD, Components: []tcap.Component{{ReturnResultNotLast: &tcap.ReturnResult{InvokeID: id}}}}
	}
	re := func(id int64) *tcap.End {
		return &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnError: &tcap.ReturnError{InvokeID: id, ErrorCode: tcap.LocalCode(1)}}}}
	}
	rej := func(id int64) *tcap.End {
		return &tcap.End{DTID: tidD, Components: []tcap.Component{{Reject: &tcap.Reject{InvokeID: &id, Problem: tcap.Problem{Invoke: ptr(wire.NewInvokeProblemInt64(1))}}}}}
	}
	runMarshalCases(t, []marshalCase{
		{name: "invoke -129", msg: beginWith(invokeC(-129)), constraint: true, constraintPath: "begin.components.element[0].basicROS.invoke.invokeId.present"},
		{name: "invoke -128", msg: beginWith(invokeC(-128)), want: corpusHex(t, "begin-invokeid--128")},
		{name: "invoke -1", msg: beginWith(invokeC(-1)), want: corpusHex(t, "begin-invokeid--1")},
		{name: "invoke 127", msg: beginWith(invokeC(127)), want: corpusHex(t, "begin-invokeid-127")},
		{name: "invoke 128", msg: beginWith(invokeC(128)), constraint: true, constraintPath: "begin.components.element[0].basicROS.invoke.invokeId.present"},
		{name: "invoke max int64", msg: beginWith(invokeC(math.MaxInt64)), constraint: true, constraintPath: "begin.components.element[0].basicROS.invoke.invokeId.present"},
		{name: "invoke 128 second", msg: beginWith(invokeC(1), invokeC(128)), constraint: true, constraintPath: "begin.components.element[1].basicROS.invoke.invokeId.present"},
		{name: "linked -129", msg: linked(-129), constraint: true},
		{name: "linked -128", msg: linked(-128), want: "62134804010203046c0ba10902010380018002013c"},
		{name: "linked 127", msg: linked(127), want: "62134804010203046c0ba10902010380017f02013c"},
		{name: "linked 128", msg: linked(128), constraint: true},
		{name: "return result last 128", msg: rrl(128), constraint: true},
		{name: "return result last -129", msg: rrl(-129), constraint: true},
		{name: "return result not last -128", msg: rrnl(-128), want: "65134804010203044904050607086c05a703020180"},
		{name: "return result not last -129", msg: rrnl(-129), constraint: true},
		{name: "return error 127", msg: re(127), want: "64104904050607086c08a30602017f020101"},
		{name: "return error 128", msg: re(128), constraint: true},
		{name: "return error -129", msg: re(-129), constraint: true},
		{name: "reject -128", msg: rej(-128), want: "64104904050607086c08a406020180810101"},
		{name: "reject 128", msg: rej(128), constraint: true},
		{name: "reject -129", msg: rej(-129), constraint: true},
	})
}

// TestMarshalCodes covers contract 3.5: local codes are INTEGER, global codes
// OBJECT IDENTIFIER (Q.773 clauses 4.2.2.3 and 4.2.2.5).
func TestMarshalCodes(t *testing.T) {
	inv := func(op tcap.Code) *tcap.Begin {
		return beginWith(tcap.Component{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: op, Parameter: hx("30050403010203")}})
	}
	runMarshalCases(t, []marshalCase{
		{name: "local 0", msg: inv(tcap.LocalCode(0)), want: corpusHex(t, "begin-opcode-0")},
		{name: "local 127", msg: inv(tcap.LocalCode(127)), want: corpusHex(t, "begin-opcode-127")},
		{name: "local 128", msg: inv(tcap.LocalCode(128)), want: corpusHex(t, "begin-opcode-128")},
		{name: "local -1", msg: inv(tcap.LocalCode(-1)), want: corpusHex(t, "begin-opcode--1")},
		{name: "local max int64", msg: beginWith(tcap.Component{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.LocalCode(math.MaxInt64)}}), want: "62174804010203046c0fa10d02010102087fffffffffffffff"},
		{name: "local min int64", msg: beginWith(tcap.Component{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.LocalCode(math.MinInt64)}}), want: "62174804010203046c0fa10d02010102088000000000000000"},
		{name: "global", msg: inv(tcap.GlobalCode("1.2.3.4")), want: corpusHex(t, "begin-global-opcode")},
		{name: "result global", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.GlobalCode("1.2.3.4"), Parameter: hx("0402aabb")}}}}}, want: "64184904050607086c10a20e020101300906032a03040402aabb"},
		{name: "invoke nil code", msg: inv(nil), is: tcap.ErrCodeNoAlternative, pathPrefix: "Components[0].Invoke"},
		{name: "return error nil code", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnError: &tcap.ReturnError{InvokeID: 1}}}}, is: tcap.ErrCodeNoAlternative, pathPrefix: "Components[0].ReturnError"},
		{name: "result nil code", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{Parameter: hx("0500")}}}}}, is: tcap.ErrCodeNoAlternative, pathPrefix: "Components[0].ReturnResultLast"},
		{name: "global empty", msg: inv(tcap.GlobalCode("")), is: tcap.ErrInvalidOID},
		{name: "global one arc", msg: inv(tcap.GlobalCode("1")), is: tcap.ErrInvalidOID},
		{name: "global not canonical", msg: inv(tcap.GlobalCode("1.02.3")), is: tcap.ErrInvalidOID},
		{name: "global second arc 40", msg: &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnError: &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.GlobalCode("1.40")}}}}, is: tcap.ErrInvalidOID},
		{name: "global arc beyond uint64", msg: inv(tcap.GlobalCode("1.2.18446744073709551616")), want: "62214804010203046c19a117020101060b2a8280808080808080800030050403010203"},
		{name: "global first subidentifier beyond uint64", msg: inv(tcap.GlobalCode("2.18446744073709551536")), want: "62204804010203046c18a116020101060a8280808080808080800030050403010203"},
	})
}

// A parameter is one complete BER value (Q.773 clause 4.2.2.4), emitted
// verbatim when it conforms to the clause 4.1.1 profile.
func TestMarshalParameters(t *testing.T) {
	inv := func(p []byte) *tcap.Begin {
		return beginWith(tcap.Component{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.LocalCode(45), Parameter: p}})
	}
	re := func(p []byte) *tcap.End {
		return &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnError: &tcap.ReturnError{InvokeID: 1, ErrorCode: tcap.LocalCode(1), Parameter: p}}}}
	}
	rr := func(p []byte) *tcap.End {
		return &tcap.End{DTID: tidD, Components: []tcap.Component{{ReturnResultLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(45), Parameter: p}}}}}
	}
	runMarshalCases(t, []marshalCase{
		{name: "invoke nil", msg: inv(nil), want: "62104804010203046c08a10602010102012d"},
		{name: "invoke primitive", msg: inv(hx("0402aabb")), want: "62144804010203046c0ca10a02010102012d0402aabb"},
		{name: "invoke empty", msg: inv([]byte{}), is: ber.ErrTruncated},
		{name: "invoke two values", msg: inv(hx("0401aa0401bb")), is: ber.ErrExtraData},
		{name: "invoke trailing octet", msg: inv(hx("0401aa00")), is: ber.ErrExtraData},
		{name: "invoke truncated", msg: inv(hx("0402aa")), is: ber.ErrTruncated},
		{name: "invoke tag only", msg: inv(hx("30")), is: ber.ErrTruncated},
		// X.690 (02/2021) clause 8.1.3.2: a primitive value has a definite length.
		{name: "invoke indefinite primitive", msg: inv(hx("0480aa0000")), is: ber.ErrInvalidLength},
		{name: "invoke indefinite missing end-of-contents", msg: inv(hx("30800403010203")), is: ber.ErrTruncated},
		// Q.773 clause 4.1.1 applies inside the parameter.
		{name: "invoke outer length not minimal", msg: inv(hx("3081050403010203")), constraint: true},
		{name: "invoke inner length not minimal", msg: inv(hx("3006048103010203")), constraint: true},
		{name: "invoke indefinite constructed", msg: inv(hx("308004030102030000")), want: "62194804010203046c11a10f02010102012d308004030102030000"},
		{name: "second component", msg: beginWith(invokeC(1), tcap.Component{Invoke: &tcap.Invoke{InvokeID: 2, OpCode: tcap.LocalCode(60), Parameter: hx("0401aa0401bb")}}), is: ber.ErrExtraData},
		{name: "return error nil", msg: re(nil), want: corpusHex(t, "end-error-local-no-parameter")},
		{name: "return error empty", msg: re([]byte{}), is: ber.ErrTruncated},
		{name: "return error two values", msg: re(hx("05000500")), is: ber.ErrExtraData},
		{name: "result nil", msg: rr(nil), is: ber.ErrTruncated},
		{name: "result empty", msg: rr([]byte{}), is: ber.ErrTruncated},
		{name: "result trailing octet", msg: rr(hx("30040402aabbff")), is: ber.ErrExtraData},
		{name: "result not last nil", msg: &tcap.Continue{OTID: tidO, DTID: tidD, Components: []tcap.Component{{ReturnResultNotLast: &tcap.ReturnResult{InvokeID: 1, Result: &tcap.Result{OpCode: tcap.LocalCode(45)}}}}}, is: ber.ErrTruncated},
	})
}

// TestMarshalReject covers contract 3.7.
func TestMarshalReject(t *testing.T) {
	rej := func(p tcap.Problem) *tcap.End {
		return &tcap.End{DTID: tidD, Components: []tcap.Component{{Reject: &tcap.Reject{InvokeID: ptr[int64](1), Problem: p}}}}
	}
	runMarshalCases(t, []marshalCase{
		{name: "no problem", msg: rej(tcap.Problem{}), is: tcap.ErrProblemNoAlternative, pathPrefix: "Components[0].Reject"},
		{name: "general and invoke", msg: rej(tcap.Problem{General: ptr(wire.GeneralProblemMistypedPDUValue()), Invoke: ptr(wire.InvokeProblemDuplicateInvocationValue())}), is: tcap.ErrProblemMultipleAlternatives, pathPrefix: "Components[0].Reject"},
		{name: "return result and return error", msg: rej(tcap.Problem{ReturnResult: ptr(wire.ReturnResultProblemMistypedResultValue()), ReturnError: ptr(wire.ReturnErrorProblemUnexpectedErrorValue())}), is: tcap.ErrProblemMultipleAlternatives},
		// Q.773 Table 25: general [0], invoke [1], return result [2], return error [3].
		{name: "general mistyped", msg: rej(tcap.Problem{General: ptr(wire.GeneralProblemMistypedPDUValue())}), want: "64104904050607086c08a406020101800101"},
		{name: "return error unexpected error", msg: rej(tcap.Problem{ReturnError: ptr(wire.ReturnErrorProblemUnexpectedErrorValue())}), want: "64104904050607086c08a406020101830103"},
	})
}

// TestMarshalAbort covers contract 3.8.
func TestMarshalAbort(t *testing.T) {
	runMarshalCases(t, []marshalCase{
		{name: "cause and dialogue", msg: &tcap.Abort{DTID: tidD, PAbortCause: ptr(wire.PAbortCauseResourceLimitationValue()), Dialogue: abrtUserD(nil)}, is: tcap.ErrAbortMultipleReasons},
		{name: "cause 128", msg: &tcap.Abort{DTID: tidD, PAbortCause: ptr(wire.NewPAbortCauseInt64(128))}, constraint: true},
		{name: "cause -1", msg: &tcap.Abort{DTID: tidD, PAbortCause: ptr(wire.NewPAbortCauseInt64(-1))}, constraint: true},
	})
}

// TestMarshalDialoguePlacement is ITU-T Q.774 (06/97) Table 3 (contract 3.9):
// every dialogue alternative in every message type.
func TestMarshalDialoguePlacement(t *testing.T) {
	type alt struct {
		name string
		d    func(abort bool) *tcap.Dialogue
		hex  func(abort bool) string
	}
	alts := []alt{
		{"Request", func(bool) *tcap.Dialogue { return aarqD(pv1(), acn3, nil) }, func(bool) string { return dialoguePortion(hexDialogueAS, hexAARQ) }},
		{"Response", func(abort bool) *tcap.Dialogue { return aareD(pv1(), !abort) }, func(abort bool) string {
			if abort {
				return dialoguePortion(hexDialogueAS, hexAARERej)
			}
			return dialoguePortion(hexDialogueAS, hexAAREAcc)
		}},
		{"Abort", func(bool) *tcap.Dialogue { return abrtUserD(nil) }, func(bool) string { return dialoguePortion(hexDialogueAS, hexABRTUser) }},
		{"Unidirectional", func(bool) *tcap.Dialogue { return audtD(pv1(), acn3) }, func(bool) string { return dialoguePortion(hexUniAS, hexAUDT) }},
		{"Opaque", func(bool) *tcap.Dialogue { return &tcap.Dialogue{Opaque: opaqueE()} }, func(bool) string { return tlv("6b", hexOpaqueExt) }},
	}
	allowed := map[string]map[string]bool{
		"Begin":          {"Request": true},
		"Continue":       {"Response": true, "Opaque": true},
		"End":            {"Response": true, "Opaque": true},
		"Abort":          {"Response": true, "Abort": true, "Opaque": true},
		"Unidirectional": {"Unidirectional": true},
	}
	inv := tlv("6c", hexInvoke)
	var cases []marshalCase
	for _, a := range alts {
		build := map[string]func() (tcap.Message, string){
			"Begin": func() (tcap.Message, string) {
				return beginD(a.d(false)), tlv("62", hexOTID, a.hex(false), inv)
			},
			"Continue": func() (tcap.Message, string) {
				return &tcap.Continue{OTID: tidO, DTID: tidD, Dialogue: a.d(false), Components: []tcap.Component{invokeC(1)}}, tlv("65", hexOTID, hexDTID, a.hex(false), inv)
			},
			"End": func() (tcap.Message, string) {
				return &tcap.End{DTID: tidD, Dialogue: a.d(false), Components: []tcap.Component{invokeC(1)}}, tlv("64", hexDTID, a.hex(false), inv)
			},
			"Abort": func() (tcap.Message, string) {
				return &tcap.Abort{DTID: tidD, Dialogue: a.d(true)}, tlv("67", hexDTID, a.hex(true))
			},
			"Unidirectional": func() (tcap.Message, string) {
				return &tcap.Unidirectional{Dialogue: a.d(false), Components: []tcap.Component{invokeC(1)}}, tlv("61", a.hex(false), inv)
			},
		}
		for _, mt := range []string{"Begin", "Continue", "End", "Abort", "Unidirectional"} {
			msg, want := build[mt]()
			c := marshalCase{name: mt + "/" + a.name, msg: msg}
			if allowed[mt][a.name] {
				c.want = want
			} else if (mt == "Begin" || mt == "Unidirectional") && a.name == "Opaque" {
				c.constraint = true
			} else {
				c.is = tcap.ErrUnexpectedDialoguePDU
				c.pathPrefix = "Dialogue"
			}
			cases = append(cases, c)
		}
	}
	runMarshalCases(t, cases)
}

// TestMarshalDialogueRules covers the rest of contract 3.9.
func TestMarshalDialogueRules(t *testing.T) {
	rsd := func(d tcap.ResultSourceDiagnostic) *tcap.Continue {
		dlg := aareD(pv1(), true)
		dlg.Response.ResultSourceDiagnostic = d
		return &tcap.Continue{OTID: tidO, DTID: tidD, Dialogue: dlg}
	}
	providerAbort := func(ui []tcap.External) *tcap.Abort {
		return &tcap.Abort{DTID: tidD, Dialogue: &tcap.Dialogue{Abort: &tcap.ABRT{AbortSource: wire.ABRTSourceDialogueServiceProviderValue(), UserInformation: ui}}}
	}
	aareIn := func(version *runtime.BitString) *tcap.Continue {
		return &tcap.Continue{OTID: tidO, DTID: tidD, Dialogue: aareD(version, true)}
	}
	runMarshalCases(t, []marshalCase{
		{name: "no alternative", msg: beginD(&tcap.Dialogue{}), is: tcap.ErrDialogueNoAlternative, pathPrefix: "Dialogue"},
		{name: "request and opaque", msg: beginD(&tcap.Dialogue{Request: aarqD(pv1(), acn3, nil).Request, Opaque: opaqueE()}), is: tcap.ErrDialogueMultipleAlternatives, pathPrefix: "Dialogue"},
		{name: "response and abort", msg: &tcap.Abort{DTID: tidD, Dialogue: &tcap.Dialogue{Response: aareD(pv1(), false).Response, Abort: abrtUserD(nil).Abort}}, is: tcap.ErrDialogueMultipleAlternatives},

		// Q.774 Table 3: AARE[accept] in Continue and End, AARE[rejected] in Abort.
		{name: "continue rejecting AARE", msg: &tcap.Continue{OTID: tidO, DTID: tidD, Dialogue: aareD(pv1(), false)}, is: tcap.ErrUnexpectedDialogueResult, pathPrefix: "Dialogue"},
		{name: "end rejecting AARE", msg: &tcap.End{DTID: tidD, Dialogue: aareD(pv1(), false)}, is: tcap.ErrUnexpectedDialogueResult},
		{name: "abort accepting AARE", msg: &tcap.Abort{DTID: tidD, Dialogue: aareD(pv1(), true)}, is: tcap.ErrUnexpectedDialogueResult},

		// Q.774 clause 3.2.2.1: the provider ABRT has no user information.
		{name: "provider ABRT with user information", msg: providerAbort([]tcap.External{mapUserAbortExt()}), is: tcap.ErrUnexpectedUserInformation, pathPrefix: "Dialogue"},
		{name: "provider ABRT with empty user information", msg: providerAbort([]tcap.External{}), is: tcap.ErrUnexpectedUserInformation},
		{name: "user ABRT empty user information", msg: &tcap.Abort{DTID: tidD, Dialogue: abrtUserD([]tcap.External{})}, want: tlv("67", hexDTID, dialoguePortion(hexDialogueAS, "6405800100be00"))},

		{name: "RSD none", msg: rsd(tcap.ResultSourceDiagnostic{}), is: tcap.ErrResultSourceDiagnosticNoAlternative, path: "Dialogue.Response.ResultSourceDiagnostic"},
		{name: "RSD both", msg: rsd(tcap.ResultSourceDiagnostic{
			DialogueServiceUser:     userNull(),
			DialogueServiceProvider: ptr(wire.AssociateSourceDiagnosticDialogueServiceProviderValueNullValue()),
		}), is: tcap.ErrResultSourceDiagnosticMultipleAlternatives, path: "Dialogue.Response.ResultSourceDiagnostic"},
		{name: "RSD provider no reason", msg: rsd(tcap.ResultSourceDiagnostic{DialogueServiceProvider: ptr(wire.AssociateSourceDiagnosticDialogueServiceProviderValueNoReasonGivenValue())}),
			want: tlv("65", hexOTID, hexDTID, dialoguePortion(hexDialogueAS, tlv("61", hexPV1, hexACN3, "a203020100", "a305a203020101")))},

		// Protocol version, Q.774 clause 3.2.3.
		{name: "AARQ version1 and bit 1", msg: beginD(aarqD(pv("c0", 2), acn3, nil)), want: "62374804010203046b1e281c060700118605010101a011600f800206c0a1090607040000010014036c0fa10d02010102012d30050403010203"},
		{name: "AARQ version1 with trailing zero bits", msg: beginD(aarqD(pv("80", 8), acn3, nil)), want: "62374804010203046b1e281c060700118605010101a011600f80020080a1090607040000010014036c0fa10d02010102012d30050403010203"},
		{name: "AARQ only bit 1", msg: beginD(aarqD(pv("40", 2), acn3, nil)), is: tcap.ErrUnsupportedProtocolVersion, pathPrefix: "Dialogue"},
		{name: "AARQ empty bit string", msg: beginD(aarqD(&runtime.BitString{}, acn3, nil)), is: tcap.ErrUnsupportedProtocolVersion},
		{name: "AARQ bit 0 clear", msg: beginD(aarqD(pv("00", 1), acn3, nil)), is: tcap.ErrUnsupportedProtocolVersion},
		{name: "AUDT nil", msg: &tcap.Unidirectional{Dialogue: audtD(nil, acn3), Components: []tcap.Component{invokeC(1)}}, want: tlv("61", dialoguePortion(hexUniAS, tlv("60", hexACN3)), tlv("6c", hexInvoke))},
		{name: "AUDT only bit 1", msg: &tcap.Unidirectional{Dialogue: audtD(pv("40", 2), acn3), Components: []tcap.Component{invokeC(1)}}, is: tcap.ErrUnsupportedProtocolVersion},
		{name: "AARE version1", msg: aareIn(pv1()), want: tlv("65", hexOTID, hexDTID, dialoguePortion(hexDialogueAS, hexAAREAcc))},
		{name: "AARE version1 with trailing zero bits", msg: aareIn(pv("80", 8)), want: "65384804010203044904050607086b2a2828060700118605010101a01d611b80020080a109060704000001001403a203020100a305a103020100"},
		{name: "AARE version1 and bit 1", msg: aareIn(pv("c0", 2)), is: tcap.ErrUnsupportedProtocolVersion, pathPrefix: "Dialogue"},
		{name: "AARE only bit 1", msg: aareIn(pv("40", 2)), is: tcap.ErrUnsupportedProtocolVersion},
		{name: "AARE bit 0 clear", msg: aareIn(pv("00", 1)), is: tcap.ErrUnsupportedProtocolVersion},
		{name: "AARE empty bit string", msg: aareIn(&runtime.BitString{}), is: tcap.ErrUnsupportedProtocolVersion},

		// Application context name, contract 3.9 and 3.11.
		{name: "AARQ ACN empty", msg: beginD(aarqD(pv1(), "", nil)), is: tcap.ErrInvalidOID, pathPrefix: "Dialogue"},
		{name: "AARQ ACN first arc 3", msg: beginD(aarqD(pv1(), "3.1", nil)), is: tcap.ErrInvalidOID},
		{name: "AARQ ACN beyond uint64", msg: beginD(aarqD(pv1(), "0.4.18446744073709551616", nil)), want: "623b4804010203046b222820060700118605010101a015601380020780a10d060b04828080808080808080006c0fa10d02010102012d30050403010203"},
		{name: "AARE ACN second arc 40", msg: &tcap.Continue{OTID: tidO, DTID: tidD, Dialogue: &tcap.Dialogue{Response: &tcap.AARE{
			ApplicationContextName: "0.40", ResultSourceDiagnostic: tcap.ResultSourceDiagnostic{DialogueServiceUser: userNull()},
		}}}, is: tcap.ErrInvalidOID},
		{name: "AUDT ACN with space", msg: &tcap.Unidirectional{Dialogue: audtD(nil, "0.4 .0"), Components: []tcap.Component{invokeC(1)}}, is: tcap.ErrInvalidOID},
	})
}

// TestMarshalExternal covers contract 3.10 and the EXTERNAL encodings of
// ITU-T X.690 (02/2021) clause 8.18 (Q.773 Tables 49 to 53).
func TestMarshalExternal(t *testing.T) {
	opaque := func(e tcap.External) *tcap.End {
		return &tcap.End{DTID: tidD, Dialogue: &tcap.Dialogue{Opaque: &e}}
	}
	userInfo := func(e tcap.External) *tcap.Begin {
		return &tcap.Begin{OTID: tidO, Dialogue: aarqD(pv1(), acn3, []tcap.External{mapUserAbortExt(), e})}
	}
	single := hx("0402aabb")
	runMarshalCases(t, []marshalCase{
		{name: "octet-aligned", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalOctetAligned, OctetAligned: hx("010203")}), want: "64144904050607086b0c280a06032a03048103010203"},
		{name: "single-ASN1-type", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: single}), want: "64154904050607086b0d280b06032a0304a0040402aabb"},
		{name: "arbitrary", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalArbitrary, Arbitrary: runtime.BitString{Bytes: hx("f0"), BitLength: 4}}), want: "64134904050607086b0b280906032a0304820204f0"},
		{name: "all identification fields", msg: opaque(tcap.External{
			DirectReference: "1.2.3.4", IndirectReference: big.NewInt(5), DataValueDescriptor: ptr("abc"),
			Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: single,
		}), constraint: true},
		{name: "indirect reference only", msg: &tcap.Abort{DTID: tidD, Dialogue: &tcap.Dialogue{Opaque: &tcap.External{
			IndirectReference: big.NewInt(7), Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: hx("0500"),
		}}}, constraint: true},
		{name: "single-ASN1-type verbatim", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: hx("3081020500")}),
			constraint: true},
		{name: "user information two elements", msg: userInfo(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalOctetAligned, OctetAligned: hx("0102")}),
			want: "62444804010203046b3c283a060700118605010101a02f602d80020780a109060704000001001403be1c280f060704000001010101a004a4028000280906032a030481020102"},
		{name: "user information present empty", msg: &tcap.Begin{OTID: tidO, Dialogue: aarqD(pv1(), acn3, []tcap.External{}), Components: []tcap.Component{invokeC(1)}},
			want: "62394804010203046b20281e060700118605010101a013601180020780a109060704000001001403be006c0fa10d02010102012d30050403010203"},

		{name: "encoding zero", msg: opaque(tcap.External{DirectReference: "1.2.3.4", SingleASN1Type: single}), is: tcap.ErrExternalEncoding, pathPrefix: "Dialogue"},
		{name: "encoding four", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalEncoding(4), SingleASN1Type: single}), is: tcap.ErrExternalEncoding},
		{name: "single with octet-aligned set", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: single, OctetAligned: hx("01")}), is: tcap.ErrExternalEncoding},
		{name: "single with arbitrary set", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: single, Arbitrary: runtime.BitString{Bytes: hx("ff"), BitLength: 8}}), is: tcap.ErrExternalEncoding},
		{name: "octet-aligned with single set", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalOctetAligned, OctetAligned: hx("01"), SingleASN1Type: single}), is: tcap.ErrExternalEncoding},
		{name: "arbitrary with octet-aligned set", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalArbitrary, Arbitrary: runtime.BitString{Bytes: hx("ff"), BitLength: 8}, OctetAligned: hx("01")}), is: tcap.ErrExternalEncoding},
		{name: "user information encoding zero", msg: userInfo(tcap.External{DirectReference: "1.2.3.4"}), is: tcap.ErrExternalEncoding, pathPrefix: "Dialogue.Request"},
		{name: "single nil", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type}), is: ber.ErrTruncated},
		{name: "single two values", msg: opaque(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: hx("05000500")}), is: ber.ErrExtraData},
		{name: "single truncated", msg: userInfo(tcap.External{DirectReference: "1.2.3.4", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: hx("0403aabb")}), is: ber.ErrTruncated},
		{name: "direct reference invalid", msg: opaque(tcap.External{DirectReference: "1.2.x", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: single}), is: tcap.ErrInvalidOID},
		{name: "user information direct reference invalid", msg: userInfo(tcap.External{DirectReference: "7.1", Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: single}), is: tcap.ErrInvalidOID},
		// X.690 (02/2021) clause 8.18.4 Table 2: an EXTERNAL needs a direct
		// or an indirect reference; go-asn1 reports ber.ErrInvalidValue
		// (runtime/ber/external.go, encodeExternal).
		{name: "no reference", msg: opaque(tcap.External{Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: single}), is: ber.ErrInvalidValue},
		{name: "user information no reference", msg: userInfo(tcap.External{Encoding: runtime.ExternalOctetAligned, OctetAligned: hx("01")}), is: ber.ErrInvalidValue},
	})
}
