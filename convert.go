package tcap

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	asn1tcap "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// --- TCMessage <-> TCAP ---

func convertTCMessageToTCAP(msg *asn1tcap.TCMessage) (TCAP, error) {
	switch msg.Choice {
	case asn1tcap.TCMessageChoiceBegin:
		if msg.Begin == nil {
			return nil, fmt.Errorf("TCMessage begin is nil")
		}
		return convertBeginToBeginTCAP(msg.Begin)
	case asn1tcap.TCMessageChoiceEnd:
		if msg.End == nil {
			return nil, fmt.Errorf("TCMessage end is nil")
		}
		return convertEndToEndTCAP(msg.End)
	case asn1tcap.TCMessageChoiceContinue:
		if msg.Continue == nil {
			return nil, fmt.Errorf("TCMessage continue is nil")
		}
		return convertContinueToContinueTCAP(msg.Continue)
	case asn1tcap.TCMessageChoiceAbort:
		if msg.Abort == nil {
			return nil, fmt.Errorf("TCMessage abort is nil")
		}
		return convertAbortToAbortTCAP(msg.Abort)
	case asn1tcap.TCMessageChoiceUnidirectional:
		if msg.Unidirectional == nil {
			return nil, fmt.Errorf("TCMessage unidirectional is nil")
		}
		return convertUnidirectionalToUnidirectionalTCAP(msg.Unidirectional)
	default:
		return nil, fmt.Errorf("unknown TCMessage choice: %d", msg.Choice)
	}
}

// --- Decode: go-asn1 -> public types ---

func convertBeginToBeginTCAP(bn *asn1tcap.Begin) (*BeginTCAP, error) {
	result := &BeginTCAP{
		Otid:            TransactionID(bn.Otid),
		componentsIndef: bn.ComponentsIndef_,
	}
	if bn.DialoguePortion != nil {
		dlg, err := convertDialoguePortionToDialogue(bn.DialoguePortion)
		if err != nil {
			return nil, fmt.Errorf("converting dialogue: %w", err)
		}
		result.Dialogue = dlg
	}
	if bn.Components != nil {
		comps, err := convertComponentPortionToComponents(bn.Components)
		if err != nil {
			return nil, fmt.Errorf("converting components: %w", err)
		}
		result.Components = comps
	}
	return result, nil
}

func convertEndToEndTCAP(ed *asn1tcap.End) (*EndTCAP, error) {
	result := &EndTCAP{
		Dtid:            TransactionID(ed.Dtid),
		componentsIndef: ed.ComponentsIndef_,
	}
	if ed.DialoguePortion != nil {
		dlg, err := convertDialoguePortionToDialogue(ed.DialoguePortion)
		if err != nil {
			return nil, fmt.Errorf("converting dialogue: %w", err)
		}
		result.Dialogue = dlg
	}
	if ed.Components != nil {
		comps, err := convertComponentPortionToComponents(ed.Components)
		if err != nil {
			return nil, fmt.Errorf("converting components: %w", err)
		}
		result.Components = comps
	}
	return result, nil
}

func convertContinueToContinueTCAP(ct *asn1tcap.Continue) (*ContinueTCAP, error) {
	result := &ContinueTCAP{
		Otid:            TransactionID(ct.Otid),
		Dtid:            TransactionID(ct.Dtid),
		componentsIndef: ct.ComponentsIndef_,
	}
	if ct.DialoguePortion != nil {
		dlg, err := convertDialoguePortionToDialogue(ct.DialoguePortion)
		if err != nil {
			return nil, fmt.Errorf("converting dialogue: %w", err)
		}
		result.Dialogue = dlg
	}
	if ct.Components != nil {
		comps, err := convertComponentPortionToComponents(ct.Components)
		if err != nil {
			return nil, fmt.Errorf("converting components: %w", err)
		}
		result.Components = comps
	}
	return result, nil
}

func convertAbortToAbortTCAP(ab *asn1tcap.Abort) (*AbortTCAP, error) {
	result := &AbortTCAP{
		Dtid: TransactionID(ab.Dtid),
	}
	if ab.Reason != nil {
		switch ab.Reason.Choice {
		case asn1tcap.AbortReasonChoicePAbortCause:
			if ab.Reason.PAbortCause != nil {
				result.PAbortCause = int64Ptr(*ab.Reason.PAbortCause)
			}
		case asn1tcap.AbortReasonChoiceUAbortCause:
			if ab.Reason.UAbortCause != nil {
				result.UAbortCause = ab.Reason.UAbortCause.Bytes
			}
		}
	}
	return result, nil
}

func convertUnidirectionalToUnidirectionalTCAP(ud *asn1tcap.Unidirectional) (*UnidirectionalTCAP, error) {
	result := &UnidirectionalTCAP{}
	if ud.DialoguePortion != nil {
		dlg, err := convertDialoguePortionToDialogue(ud.DialoguePortion)
		if err != nil {
			return nil, fmt.Errorf("converting dialogue: %w", err)
		}
		result.Dialogue = dlg
	}
	comps, err := convertComponentPortionToComponents(ud.Components)
	if err != nil {
		return nil, fmt.Errorf("converting components: %w", err)
	}
	result.Components = comps
	return result, nil
}

// --- Components ---

func convertComponentPortionToComponents(cp asn1tcap.ComponentPortion) ([]Component, error) {
	var result []Component
	for _, c := range cp {
		comp, err := convertASN1ComponentToComponent(&c)
		if err != nil {
			return nil, err
		}
		result = append(result, comp)
	}
	return result, nil
}

func convertASN1ComponentToComponent(c *asn1tcap.Component) (Component, error) {
	var result Component

	var ros *asn1tcap.ROS
	isReturnResultNotLast := false

	switch c.Choice {
	case asn1tcap.ComponentChoiceBasicROS:
		ros = c.BasicROS
	case asn1tcap.ComponentChoiceReturnResultNotLast:
		ros = c.ReturnResultNotLast
		isReturnResultNotLast = true
	default:
		return result, fmt.Errorf("unknown Component choice: %d", c.Choice)
	}

	if ros == nil {
		return result, fmt.Errorf("ROS is nil for Component choice %d", c.Choice)
	}

	switch ros.Choice {
	case asn1tcap.ROSChoiceInvoke:
		if ros.Invoke == nil {
			return result, fmt.Errorf("invoke is nil")
		}
		inv, err := convertASN1InvokeToInvoke(ros.Invoke)
		if err != nil {
			return result, fmt.Errorf("converting invoke: %w", err)
		}
		result.Invoke = inv

	case asn1tcap.ROSChoiceReturnResult:
		if ros.ReturnResult == nil {
			return result, fmt.Errorf("returnResult is nil")
		}
		rr, err := convertASN1ReturnResultToReturnResult(ros.ReturnResult)
		if err != nil {
			return result, fmt.Errorf("converting returnResult: %w", err)
		}
		if isReturnResultNotLast {
			result.ReturnResultNotLast = rr
		} else {
			result.ReturnResultLast = rr
		}

	case asn1tcap.ROSChoiceReturnError:
		if ros.ReturnError == nil {
			return result, fmt.Errorf("returnError is nil")
		}
		re, err := convertASN1ReturnErrorToReturnError(ros.ReturnError)
		if err != nil {
			return result, fmt.Errorf("converting returnError: %w", err)
		}
		result.ReturnError = re

	case asn1tcap.ROSChoiceReject:
		if ros.Reject == nil {
			return result, fmt.Errorf("reject is nil")
		}
		rj := convertASN1RejectToReject(ros.Reject)
		result.Reject = rj

	default:
		return result, fmt.Errorf("unknown ROS choice: %d", ros.Choice)
	}

	return result, nil
}

func convertASN1InvokeToInvoke(inv *asn1tcap.Invoke) (*Invoke, error) {
	result := &Invoke{}

	// InvokeID
	if inv.InvokeId.Choice == asn1tcap.InvokeIdChoicePresent && inv.InvokeId.Present != nil {
		result.InvokeID = int(*inv.InvokeId.Present)
	}

	// LinkedID
	if inv.LinkedId != nil && inv.LinkedId.Choice == asn1tcap.InvokeLinkedIdChoicePresent && inv.LinkedId.Present != nil {
		if inv.LinkedId.Present.Choice == asn1tcap.InvokeIdChoicePresent && inv.LinkedId.Present.Present != nil {
			result.LinkedID = intPtr(int(*inv.LinkedId.Present.Present))
		}
	}

	// OpCode — decode from RawValue
	opCode, err := decodeOpCodeFromRawValue(inv.Opcode)
	if err != nil {
		return nil, fmt.Errorf("decoding opcode: %w", err)
	}
	result.OpCode = opCode

	// Parameter
	if inv.Argument != nil {
		result.Parameter = inv.Argument.Bytes
	}

	return result, nil
}

func convertASN1ReturnResultToReturnResult(rr *asn1tcap.ReturnResult) (*ReturnResult, error) {
	result := &ReturnResult{}

	// InvokeID
	if rr.InvokeId.Choice == asn1tcap.InvokeIdChoicePresent && rr.InvokeId.Present != nil {
		result.InvokeID = int(*rr.InvokeId.Present)
	}

	// Result contains opcode + parameter as a SEQUENCE RawValue
	if rr.Result != nil && len(rr.Result.Bytes) > 0 {
		opCode, param, err := decodeResultRetRes(rr.Result.Bytes)
		if err != nil {
			return nil, fmt.Errorf("decoding result: %w", err)
		}
		result.OpCode = &opCode
		result.Parameter = param
	}

	return result, nil
}

func convertASN1ReturnErrorToReturnError(re *asn1tcap.ReturnError) (*ReturnError, error) {
	result := &ReturnError{}

	// InvokeID
	if re.InvokeId.Choice == asn1tcap.InvokeIdChoicePresent && re.InvokeId.Present != nil {
		result.InvokeID = int(*re.InvokeId.Present)
	}

	// ErrorCode — decode from RawValue
	errCode, err := decodeOpCodeFromRawValue(re.Errcode)
	if err != nil {
		return nil, fmt.Errorf("decoding error code: %w", err)
	}
	result.ErrorCode = errCode

	// Parameter
	if re.Parameter != nil {
		result.Parameter = re.Parameter.Bytes
	}

	return result, nil
}

func convertASN1RejectToReject(rj *asn1tcap.Reject) *Reject {
	result := &Reject{}

	// InvokeID — can be present (integer) or absent (null = not derivable)
	if rj.InvokeId.Choice == asn1tcap.InvokeIdChoicePresent && rj.InvokeId.Present != nil {
		result.InvokeID = intPtr(int(*rj.InvokeId.Present))
	}
	// if Absent or unset, InvokeID stays nil (not derivable)

	// Problem CHOICE
	switch rj.Problem.Choice {
	case asn1tcap.OperationsRejectProblemChoiceGeneral:
		result.GeneralProblem = rj.Problem.General
	case asn1tcap.OperationsRejectProblemChoiceInvoke:
		result.InvokeProblem = rj.Problem.Invoke
	case asn1tcap.OperationsRejectProblemChoiceReturnResult:
		result.ReturnResultProblem = rj.Problem.ReturnResult
	case asn1tcap.OperationsRejectProblemChoiceReturnError:
		result.ReturnErrorProblem = rj.Problem.ReturnError
	}

	return result
}

// --- Dialogue decode ---

func convertDialoguePortionToDialogue(dp *asn1tcap.DialoguePortion) (*Dialogue, error) {
	result := &Dialogue{}

	// The DialoguePortion is an EXTERNAL wrapper containing a DialoguePDU.
	// dp.Bytes contains the raw bytes inside the [APPLICATION 11] tag.
	// This is an EXTERNAL encoding: OID + single-ASN1-type wrapper.
	data := dp.Bytes
	if len(data) == 0 {
		return result, nil
	}

	// Parse the EXTERNAL structure manually:
	// EXTERNAL ::= [UNIVERSAL 8] IMPLICIT SEQUENCE {
	//   direct-reference OBJECT IDENTIFIER OPTIONAL,
	//   ...
	//   encoding CHOICE { single-ASN1-type [0] ABSTRACT-SYNTAX.&Type }
	// }
	// In TCAP, the encoding is: OID + [0] EXPLICIT DialoguePDU

	offset := 0

	// Decode the EXTERNAL's outer TLV — it may be encoded as a SEQUENCE (0x30)
	// or as EXTERNAL (0x28). We need its content.
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr == nil && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 8) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
		// Strip EXTERNAL or SEQUENCE wrapper
		_, _, innerData, err := ber.DecodeTLV(data)
		if err != nil {
			return nil, fmt.Errorf("decoding EXTERNAL wrapper: %w", err)
		}
		data = innerData
		offset = 0
	}

	// Decode direct-reference (OID)
	if offset < len(data) {
		pt, pe := ber.PeekTag(data[offset:])
		if pe == nil && pt.Class == tag.ClassUniversal && pt.Number == 6 {
			oid, n, err := ber.DecodeObjectIdentifier(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("decoding dialogue OID: %w", err)
			}
			result.DialogAsId = oid
			offset += n
		}
	}

	// Decode encoding [0] EXPLICIT — the single-ASN1-type wrapper
	if offset < len(data) {
		pt, pe := ber.PeekTag(data[offset:])
		if pe == nil && pt.Class == tag.ClassContextSpecific && pt.Number == 0 {
			_, _, innerData, err := ber.DecodeTLV(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("decoding dialogue encoding wrapper: %w", err)
			}
			// innerData contains the DialoguePDU (or UniDialoguePDU)
			if err := decodeDialoguePDU(innerData, result); err != nil {
				return nil, err
			}
		}
	}

	return result, nil
}

func decodeDialoguePDU(data []byte, dlg *Dialogue) error {
	if len(data) == 0 {
		return nil
	}

	// Try DialoguePDU first (AARQ [APPLICATION 0], AARE [APPLICATION 1], ABRT [APPLICATION 4])
	peekTag, err := ber.PeekTag(data)
	if err != nil {
		return fmt.Errorf("peeking dialogue PDU tag: %w", err)
	}

	if peekTag.Class == tag.ClassApplication {
		switch peekTag.Number {
		case 0:
			// Could be AARQ (DialogueRequest) or AUDT (UniDialogueRequest)
			// They share the same APPLICATION 0 tag, differentiation is by DialogAsId OID
			return decodeAARQorAUDT(data, dlg)
		case 1:
			// AARE (DialogueResponse)
			var aare asn1tcap.AAREApdu
			if unmErr := aare.UnmarshalBER(data); unmErr != nil {
				return fmt.Errorf("decoding AARE: %w", unmErr)
			}
			dlg.Response = convertAAREToDialogueResponse(&aare)
			return nil
		case 4:
			// ABRT (DialogueAbort)
			var abrt asn1tcap.ABRTApdu
			if unmErr := abrt.UnmarshalBER(data); unmErr != nil {
				return fmt.Errorf("decoding ABRT: %w", unmErr)
			}
			dlg.Abort = convertABRTToDialogueAbort(&abrt)
			return nil
		}
	}

	return nil
}

func decodeAARQorAUDT(data []byte, dlg *Dialogue) error {
	var aarq asn1tcap.AARQApdu
	if unmErr := aarq.UnmarshalBER(data); unmErr != nil {
		return fmt.Errorf("decoding AARQ/AUDT: %w", unmErr)
	}
	dlg.Request = convertAARQToDialogueRequest(&aarq)
	return nil
}

func convertAARQToDialogueRequest(aarq *asn1tcap.AARQApdu) *DialogueRequest {
	result := &DialogueRequest{}

	if aarq.ProtocolVersion != nil && len(aarq.ProtocolVersion.Bytes) > 0 {
		result.ProtocolVersion = uint8Ptr(aarq.ProtocolVersion.Bytes[len(aarq.ProtocolVersion.Bytes)-1])
	}

	result.ApplicationContextName = []uint64(aarq.ApplicationContextName)

	if len(aarq.UserInformation) > 0 {
		result.UserInformation = collectUserInformationBytes(aarq.UserInformation)
	}

	return result
}

func convertAAREToDialogueResponse(aare *asn1tcap.AAREApdu) *DialogueResponse {
	result := &DialogueResponse{}

	if aare.ProtocolVersion != nil && len(aare.ProtocolVersion.Bytes) > 0 {
		result.ProtocolVersion = uint8Ptr(aare.ProtocolVersion.Bytes[len(aare.ProtocolVersion.Bytes)-1])
	}

	result.ApplicationContextName = []uint64(aare.ApplicationContextName)
	result.Result = aare.Result

	switch aare.ResultSourceDiagnostic.Choice {
	case asn1tcap.AssociateSourceDiagnosticChoiceDialogueServiceUser:
		result.ResultSourceDiagnostic.DialogueServiceUser = aare.ResultSourceDiagnostic.DialogueServiceUser
	case asn1tcap.AssociateSourceDiagnosticChoiceDialogueServiceProvider:
		result.ResultSourceDiagnostic.DialogueServiceProvider = aare.ResultSourceDiagnostic.DialogueServiceProvider
	}

	if len(aare.UserInformation) > 0 {
		result.UserInformation = collectUserInformationBytes(aare.UserInformation)
	}

	return result
}

func convertABRTToDialogueAbort(abrt *asn1tcap.ABRTApdu) *DialogueAbort {
	result := &DialogueAbort{
		AbortSource: abrt.AbortSource,
	}

	if len(abrt.UserInformation) > 0 {
		result.UserInformation = collectUserInformationBytes(abrt.UserInformation)
	}

	return result
}

func collectUserInformationBytes(userInfo []runtime.RawValue) []byte {
	if len(userInfo) == 0 {
		return nil
	}
	// Concatenate all raw value bytes
	var result []byte
	for _, rv := range userInfo {
		result = append(result, rv.Bytes...)
	}
	return result
}

// --- Encode: public types -> go-asn1 ---

func convertBeginTCAPToASN1(bn *BeginTCAP) (asn1tcap.TCMessage, error) {
	begin := asn1tcap.Begin{
		Otid:             asn1tcap.OrigTransactionID(bn.Otid),
		ComponentsIndef_: bn.componentsIndef,
	}

	if bn.Dialogue != nil {
		dp, err := convertDialogueToDialoguePortion(bn.Dialogue)
		if err != nil {
			return asn1tcap.TCMessage{}, fmt.Errorf("converting dialogue: %w", err)
		}
		begin.DialoguePortion = dp
	}

	if len(bn.Components) > 0 {
		cp, err := convertComponentsToComponentPortion(bn.Components)
		if err != nil {
			return asn1tcap.TCMessage{}, fmt.Errorf("converting components: %w", err)
		}
		begin.Components = cp
	}

	return asn1tcap.NewTCMessageBegin(begin), nil
}

func convertEndTCAPToASN1(ed *EndTCAP) (asn1tcap.TCMessage, error) {
	end := asn1tcap.End{
		Dtid:             asn1tcap.DestTransactionID(ed.Dtid),
		ComponentsIndef_: ed.componentsIndef,
	}

	if ed.Dialogue != nil {
		dp, err := convertDialogueToDialoguePortion(ed.Dialogue)
		if err != nil {
			return asn1tcap.TCMessage{}, fmt.Errorf("converting dialogue: %w", err)
		}
		end.DialoguePortion = dp
	}

	if len(ed.Components) > 0 {
		cp, err := convertComponentsToComponentPortion(ed.Components)
		if err != nil {
			return asn1tcap.TCMessage{}, fmt.Errorf("converting components: %w", err)
		}
		end.Components = cp
	}

	return asn1tcap.NewTCMessageEnd(end), nil
}

func convertContinueTCAPToASN1(ct *ContinueTCAP) (asn1tcap.TCMessage, error) {
	cont := asn1tcap.Continue{
		Otid:             asn1tcap.OrigTransactionID(ct.Otid),
		Dtid:             asn1tcap.DestTransactionID(ct.Dtid),
		ComponentsIndef_: ct.componentsIndef,
	}

	if ct.Dialogue != nil {
		dp, err := convertDialogueToDialoguePortion(ct.Dialogue)
		if err != nil {
			return asn1tcap.TCMessage{}, fmt.Errorf("converting dialogue: %w", err)
		}
		cont.DialoguePortion = dp
	}

	if len(ct.Components) > 0 {
		cp, err := convertComponentsToComponentPortion(ct.Components)
		if err != nil {
			return asn1tcap.TCMessage{}, fmt.Errorf("converting components: %w", err)
		}
		cont.Components = cp
	}

	return asn1tcap.NewTCMessageContinue(cont), nil
}

func convertAbortTCAPToASN1(ab *AbortTCAP) (asn1tcap.TCMessage, error) {
	abort := asn1tcap.Abort{
		Dtid: asn1tcap.DestTransactionID(ab.Dtid),
	}

	if ab.PAbortCause != nil {
		reason := asn1tcap.NewAbortReasonPAbortCause(*ab.PAbortCause)
		abort.Reason = &reason
	} else if ab.UAbortCause != nil {
		dp := runtime.RawValue{Bytes: ab.UAbortCause}
		reason := asn1tcap.NewAbortReasonUAbortCause(dp)
		abort.Reason = &reason
	}

	return asn1tcap.NewTCMessageAbort(abort), nil
}

func convertUnidirectionalTCAPToASN1(ud *UnidirectionalTCAP) (asn1tcap.TCMessage, error) {
	uni := asn1tcap.Unidirectional{}

	if ud.Dialogue != nil {
		dp, err := convertDialogueToDialoguePortion(ud.Dialogue)
		if err != nil {
			return asn1tcap.TCMessage{}, fmt.Errorf("converting dialogue: %w", err)
		}
		uni.DialoguePortion = dp
	}

	cp, err := convertComponentsToComponentPortion(ud.Components)
	if err != nil {
		return asn1tcap.TCMessage{}, fmt.Errorf("converting components: %w", err)
	}
	uni.Components = cp

	return asn1tcap.NewTCMessageUnidirectional(uni), nil
}

// --- Components encode ---

func convertComponentsToComponentPortion(comps []Component) (asn1tcap.ComponentPortion, error) {
	var result asn1tcap.ComponentPortion
	for _, comp := range comps {
		c, err := convertComponentToASN1Component(&comp)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, nil
}

func convertComponentToASN1Component(comp *Component) (asn1tcap.Component, error) {
	if comp.Invoke != nil {
		inv, err := convertInvokeToASN1Invoke(comp.Invoke)
		if err != nil {
			return asn1tcap.Component{}, err
		}
		ros := asn1tcap.NewROSInvoke(inv)
		return asn1tcap.NewComponentBasicROS(ros), nil
	}

	if comp.ReturnResultLast != nil {
		rr := convertReturnResultToASN1ReturnResult(comp.ReturnResultLast)
		ros := asn1tcap.NewROSReturnResult(rr)
		return asn1tcap.NewComponentBasicROS(ros), nil
	}

	if comp.ReturnResultNotLast != nil {
		rr := convertReturnResultToASN1ReturnResult(comp.ReturnResultNotLast)
		ros := asn1tcap.NewROSReturnResult(rr)
		return asn1tcap.NewComponentReturnResultNotLast(ros), nil
	}

	if comp.ReturnError != nil {
		re := convertReturnErrorToASN1ReturnError(comp.ReturnError)
		ros := asn1tcap.NewROSReturnError(re)
		return asn1tcap.NewComponentBasicROS(ros), nil
	}

	if comp.Reject != nil {
		rj := convertRejectToASN1Reject(comp.Reject)
		ros := asn1tcap.NewROSReject(rj)
		return asn1tcap.NewComponentBasicROS(ros), nil
	}

	return asn1tcap.Component{}, fmt.Errorf("component has no field set")
}

func convertInvokeToASN1Invoke(inv *Invoke) (asn1tcap.Invoke, error) {
	result := asn1tcap.Invoke{
		InvokeId: asn1tcap.NewInvokeIdPresent(int64(inv.InvokeID)),
	}

	if inv.LinkedID != nil {
		linkedInvokeId := asn1tcap.NewInvokeIdPresent(int64(*inv.LinkedID))
		linked := asn1tcap.NewInvokeLinkedIdPresent(linkedInvokeId)
		result.LinkedId = &linked
	}

	// Encode opcode as local integer
	opcodeBytes := ber.EncodeInteger(inv.OpCode)
	result.Opcode = runtime.RawValue{Bytes: opcodeBytes}

	if inv.Parameter != nil {
		param := runtime.RawValue{Bytes: inv.Parameter}
		result.Argument = &param
	}

	return result, nil
}

func convertReturnResultToASN1ReturnResult(rr *ReturnResult) asn1tcap.ReturnResult {
	result := asn1tcap.ReturnResult{
		InvokeId: asn1tcap.NewInvokeIdPresent(int64(rr.InvokeID)),
	}

	if rr.OpCode != nil || rr.Parameter != nil {
		// Encode the result SEQUENCE: opcode + parameter
		var resultBytes []byte
		if rr.OpCode != nil {
			resultBytes = append(resultBytes, ber.EncodeInteger(*rr.OpCode)...)
		}
		if rr.Parameter != nil {
			resultBytes = append(resultBytes, rr.Parameter...)
		}
		seqBytes := ber.EncodeSequence(resultBytes)
		rv := runtime.RawValue{Bytes: seqBytes}
		result.Result = &rv
	}

	return result
}

func convertReturnErrorToASN1ReturnError(re *ReturnError) asn1tcap.ReturnError {
	result := asn1tcap.ReturnError{
		InvokeId: asn1tcap.NewInvokeIdPresent(int64(re.InvokeID)),
		Errcode:  runtime.RawValue{Bytes: ber.EncodeInteger(re.ErrorCode)},
	}

	if re.Parameter != nil {
		param := runtime.RawValue{Bytes: re.Parameter}
		result.Parameter = &param
	}

	return result
}

func convertRejectToASN1Reject(rj *Reject) asn1tcap.Reject {
	result := asn1tcap.Reject{}

	if rj.InvokeID != nil {
		result.InvokeId = asn1tcap.NewInvokeIdPresent(int64(*rj.InvokeID))
	} else {
		result.InvokeId = asn1tcap.NewInvokeIdAbsent(struct{}{})
	}

	switch {
	case rj.GeneralProblem != nil:
		result.Problem = asn1tcap.NewOperationsRejectProblemGeneral(*rj.GeneralProblem)
	case rj.InvokeProblem != nil:
		result.Problem = asn1tcap.NewOperationsRejectProblemInvoke(*rj.InvokeProblem)
	case rj.ReturnResultProblem != nil:
		result.Problem = asn1tcap.NewOperationsRejectProblemReturnResult(*rj.ReturnResultProblem)
	case rj.ReturnErrorProblem != nil:
		result.Problem = asn1tcap.NewOperationsRejectProblemReturnError(*rj.ReturnErrorProblem)
	default:
		result.Problem = asn1tcap.NewOperationsRejectProblemGeneral(asn1tcap.GeneralProblemUnrecognizedPDU)
	}

	return result
}

// --- Dialogue encode ---

func convertDialogueToDialoguePortion(dlg *Dialogue) (*asn1tcap.DialoguePortion, error) {
	// Build the DialoguePDU
	var pduBytes []byte
	var err error

	if dlg.Request != nil {
		pduBytes, err = encodeDialogueRequest(dlg.Request)
	} else if dlg.Response != nil {
		pduBytes, err = encodeDialogueResponse(dlg.Response)
	} else if dlg.Abort != nil {
		pduBytes, err = encodeDialogueAbort(dlg.Abort)
	}
	if err != nil {
		return nil, err
	}

	// Build the EXTERNAL structure:
	// SEQUENCE { OID, [0] EXPLICIT dialoguePDU }
	var externalChildren []byte

	// Encode the dialogue AS OID
	dialogAsId := dlg.DialogAsId
	if dialogAsId == nil {
		dialogAsId = DefaultDialogueAsId
	}
	externalChildren = append(externalChildren, ber.EncodeObjectIdentifier(dialogAsId)...)

	// Encode [0] EXPLICIT wrapper around the DialoguePDU
	if pduBytes != nil {
		externalChildren = append(externalChildren, ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, pduBytes)...)
	}

	// Encode as EXTERNAL (tag 0x28 = UNIVERSAL 8 CONSTRUCTED)
	externalBytes := ber.EncodeConstructed(tag.Tag{Class: tag.ClassUniversal, Number: 8, Constructed: true}, externalChildren)

	dp := runtime.RawValue{Bytes: externalBytes}
	return &dp, nil
}

func encodeDialogueRequest(req *DialogueRequest) ([]byte, error) {
	aarq := asn1tcap.AARQApdu{
		ApplicationContextName: runtime.ObjectIdentifier(req.ApplicationContextName),
	}

	if req.ProtocolVersion != nil {
		aarq.ProtocolVersion = &runtime.BitString{
			Bytes:     []byte{*req.ProtocolVersion},
			BitLength: 1,
		}
	}

	if req.UserInformation != nil {
		aarq.UserInformation = []runtime.RawValue{{Bytes: req.UserInformation}}
	}

	return aarq.MarshalBER()
}

func encodeDialogueResponse(resp *DialogueResponse) ([]byte, error) {
	aare := asn1tcap.AAREApdu{
		ApplicationContextName: runtime.ObjectIdentifier(resp.ApplicationContextName),
		Result:                 resp.Result,
	}

	if resp.ProtocolVersion != nil {
		aare.ProtocolVersion = &runtime.BitString{
			Bytes:     []byte{*resp.ProtocolVersion},
			BitLength: 1,
		}
	}

	switch {
	case resp.ResultSourceDiagnostic.DialogueServiceUser != nil:
		aare.ResultSourceDiagnostic = asn1tcap.NewAssociateSourceDiagnosticDialogueServiceUser(*resp.ResultSourceDiagnostic.DialogueServiceUser)
	case resp.ResultSourceDiagnostic.DialogueServiceProvider != nil:
		aare.ResultSourceDiagnostic = asn1tcap.NewAssociateSourceDiagnosticDialogueServiceProvider(*resp.ResultSourceDiagnostic.DialogueServiceProvider)
	default:
		aare.ResultSourceDiagnostic = asn1tcap.NewAssociateSourceDiagnosticDialogueServiceUser(0)
	}

	if resp.UserInformation != nil {
		aare.UserInformation = []runtime.RawValue{{Bytes: resp.UserInformation}}
	}

	return aare.MarshalBER()
}

func encodeDialogueAbort(abrt *DialogueAbort) ([]byte, error) {
	a := asn1tcap.ABRTApdu{
		AbortSource: abrt.AbortSource,
	}

	if abrt.UserInformation != nil {
		a.UserInformation = []runtime.RawValue{{Bytes: abrt.UserInformation}}
	}

	return a.MarshalBER()
}

// --- Helpers ---

func decodeOpCodeFromRawValue(rv runtime.RawValue) (int64, error) {
	if len(rv.Bytes) == 0 {
		return 0, nil
	}
	val, _, err := ber.DecodeInteger(rv.Bytes)
	if err != nil {
		return 0, fmt.Errorf("decoding integer from RawValue: %w", err)
	}
	return val, nil
}

func decodeResultRetRes(data []byte) (int64, []byte, error) {
	// The result is a SEQUENCE containing opcode + parameter
	content, _, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return 0, nil, fmt.Errorf("decoding result SEQUENCE: %w", err)
	}

	offset := 0

	// Decode opcode
	if offset >= len(content) {
		return 0, nil, fmt.Errorf("missing opcode in result")
	}
	opCode, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return 0, nil, fmt.Errorf("decoding opcode: %w", err)
	}
	offset += n

	// Remaining bytes are the parameter
	var param []byte
	if offset < len(content) {
		param = content[offset:]
	}

	return opCode, param, nil
}
