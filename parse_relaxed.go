package tcap

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	asn1tcap "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

func parseTCMessageRelaxed(data []byte) (TCAP, error) {
	decodedTag, total, content, err := ber.DecodeTLV(data)
	if err != nil {
		return nil, err
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TCMessage", Cause: ber.ErrExtraData}
	}
	if decodedTag.Class != tag.ClassApplication || !decodedTag.Constructed {
		return nil, fmt.Errorf("expected constructed TCMessage application tag, got %s", decodedTag)
	}

	switch decodedTag.Number {
	case 1:
		return parseUnidirectionalContentRelaxed(content)
	case 2:
		return parseBeginContentRelaxed(content)
	case 4:
		return parseEndContentRelaxed(content)
	case 5:
		return parseContinueContentRelaxed(content)
	case 7:
		return parseAbortContentRelaxed(content)
	default:
		return nil, fmt.Errorf("unknown TCMessage tag %s", decodedTag)
	}
}

func parseBeginContentRelaxed(content []byte) (*BeginTCAP, error) {
	offset := 0
	otid, n, err := decodeApplicationTLV(content[offset:], 8, false, "otid")
	if err != nil {
		return nil, err
	}
	offset += n

	result := &BeginTCAP{Otid: TransactionID(copyBytes(otid))}
	if err := parseDialogueAndComponents(content, &offset, &result.Dialogue, &result.Components, &result.componentsIndef, false); err != nil {
		return nil, err
	}
	if offset != len(content) {
		return nil, &ber.DecodeError{Offset: offset, TypeName: "Begin", Cause: ber.ErrExtraData}
	}
	return result, nil
}

func parseEndContentRelaxed(content []byte) (*EndTCAP, error) {
	offset := 0
	dtid, n, err := decodeApplicationTLV(content[offset:], 9, false, "dtid")
	if err != nil {
		return nil, err
	}
	offset += n

	result := &EndTCAP{Dtid: TransactionID(copyBytes(dtid))}
	if err := parseDialogueAndComponents(content, &offset, &result.Dialogue, &result.Components, &result.componentsIndef, false); err != nil {
		return nil, err
	}
	if offset != len(content) {
		return nil, &ber.DecodeError{Offset: offset, TypeName: "End", Cause: ber.ErrExtraData}
	}
	return result, nil
}

func parseContinueContentRelaxed(content []byte) (*ContinueTCAP, error) {
	offset := 0
	otid, n, err := decodeApplicationTLV(content[offset:], 8, false, "otid")
	if err != nil {
		return nil, err
	}
	offset += n
	dtid, n, err := decodeApplicationTLV(content[offset:], 9, false, "dtid")
	if err != nil {
		return nil, err
	}
	offset += n

	result := &ContinueTCAP{
		Otid: TransactionID(copyBytes(otid)),
		Dtid: TransactionID(copyBytes(dtid)),
	}
	if err := parseDialogueAndComponents(content, &offset, &result.Dialogue, &result.Components, &result.componentsIndef, false); err != nil {
		return nil, err
	}
	if offset != len(content) {
		return nil, &ber.DecodeError{Offset: offset, TypeName: "Continue", Cause: ber.ErrExtraData}
	}
	return result, nil
}

func parseUnidirectionalContentRelaxed(content []byte) (*UnidirectionalTCAP, error) {
	offset := 0
	result := &UnidirectionalTCAP{}
	if err := parseDialogueAndComponents(content, &offset, &result.Dialogue, &result.Components, &result.componentsIndef, true); err != nil {
		return nil, err
	}
	if offset != len(content) {
		return nil, &ber.DecodeError{Offset: offset, TypeName: "Unidirectional", Cause: ber.ErrExtraData}
	}
	return result, nil
}

func parseAbortContentRelaxed(content []byte) (*AbortTCAP, error) {
	offset := 0
	dtid, n, err := decodeApplicationTLV(content[offset:], 9, false, "dtid")
	if err != nil {
		return nil, err
	}
	offset += n

	abort := asn1tcap.Abort{Dtid: asn1tcap.DestTransactionID(copyBytes(dtid))}
	if offset < len(content) {
		_, n, _, err := ber.DecodeTLV(content[offset:])
		if err != nil {
			return nil, fmt.Errorf("decoding reason: %w", err)
		}
		var reason asn1tcap.AbortReason
		if err := reason.UnmarshalBER(content[offset : offset+n]); err != nil {
			return nil, fmt.Errorf("decoding reason: %w", err)
		}
		abort.Reason = &reason
		offset += n
	}
	if offset != len(content) {
		return nil, &ber.DecodeError{Offset: offset, TypeName: "Abort", Cause: ber.ErrExtraData}
	}
	return convertAbortToAbortTCAP(&abort)
}

func parseDialogueAndComponents(content []byte, offset *int, dialogue **Dialogue, components *[]Component, componentsIndef *bool, componentsRequired bool) error {
	if hasApplicationTag(content[*offset:], 11) {
		raw, n, err := decodeApplicationTLV(content[*offset:], 11, true, "dialoguePortion")
		if err != nil {
			return err
		}
		dp := asn1tcap.DialoguePortion{Bytes: copyBytes(raw)}
		decoded, err := convertDialoguePortionToDialogue(&dp)
		if err != nil {
			return fmt.Errorf("converting dialogue: %w", err)
		}
		*dialogue = decoded
		*offset += n
	}

	if hasApplicationTag(content[*offset:], 12) {
		decoded, indef, n, err := parseComponentPortionRelaxed(content[*offset:])
		if err != nil {
			return err
		}
		*components = decoded
		*componentsIndef = indef
		*offset += n
		return nil
	}
	if componentsRequired {
		return fmt.Errorf("missing required components")
	}
	return nil
}

func parseComponentPortionRelaxed(data []byte) ([]Component, bool, int, error) {
	decodedTag, total, content, err := ber.DecodeTLV(data)
	if err != nil {
		return nil, false, 0, fmt.Errorf("decoding components: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, false, 0, fmt.Errorf("expected components tag [APPLICATION 12], got %s", decodedTag)
	}

	componentsIndef := false
	if _, tagSize, err := ber.DecodeTag(data[:total]); err == nil && tagSize < total && data[tagSize] == 0x80 {
		componentsIndef = true
	}

	var result []Component
	offset := 0
	for offset < len(content) {
		_, n, _, err := ber.DecodeTLV(content[offset:])
		if err != nil {
			return nil, false, 0, fmt.Errorf("decoding component TLV: %w", err)
		}
		component, err := parseComponentRelaxed(content[offset : offset+n])
		if err != nil {
			return nil, false, 0, err
		}
		result = append(result, component)
		offset += n
	}
	return result, componentsIndef, total, nil
}

func parseComponentRelaxed(data []byte) (Component, error) {
	decodedTag, total, raw, err := ber.DecodeTLV(data)
	if err != nil {
		return Component{}, fmt.Errorf("decoding component: %w", err)
	}
	if total != len(data) {
		return Component{}, &ber.DecodeError{Offset: total, TypeName: "Component", Cause: ber.ErrExtraData}
	}
	if decodedTag.Class == tag.ClassContextSpecific && decodedTag.Number == 7 {
		ros, err := parseROSRelaxed(raw)
		if err != nil {
			return Component{}, fmt.Errorf("decoding returnResultNotLast: %w", err)
		}
		if ros.ReturnResultLast == nil {
			return Component{}, fmt.Errorf("returnResultNotLast did not contain returnResult")
		}
		return Component{ReturnResultNotLast: ros.ReturnResultLast}, nil
	}
	return parseROSRelaxed(data)
}

func parseROSRelaxed(data []byte) (Component, error) {
	decodedTag, total, raw, err := ber.DecodeTLV(data)
	if err != nil {
		return Component{}, fmt.Errorf("decoding ROS: %w", err)
	}
	if total != len(data) {
		return Component{}, &ber.DecodeError{Offset: total, TypeName: "ROS", Cause: ber.ErrExtraData}
	}
	if decodedTag.Class != tag.ClassContextSpecific {
		return Component{}, fmt.Errorf("expected ROS context tag, got %s", decodedTag)
	}

	switch decodedTag.Number {
	case 1:
		invoke, err := parseInvokeContentRelaxed(raw)
		if err != nil {
			return Component{}, fmt.Errorf("decoding invoke: %w", err)
		}
		return Component{Invoke: invoke}, nil
	case 2:
		returnResult, err := parseReturnResultContentRelaxed(raw)
		if err != nil {
			return Component{}, fmt.Errorf("decoding returnResult: %w", err)
		}
		return Component{ReturnResultLast: returnResult}, nil
	case 3:
		returnError, err := parseReturnErrorContentRelaxed(raw)
		if err != nil {
			return Component{}, fmt.Errorf("decoding returnError: %w", err)
		}
		return Component{ReturnError: returnError}, nil
	case 4:
		reject, err := parseRejectContentRelaxed(raw)
		if err != nil {
			return Component{}, fmt.Errorf("decoding reject: %w", err)
		}
		return Component{Reject: reject}, nil
	default:
		return Component{}, fmt.Errorf("unknown ROS tag %s", decodedTag)
	}
}

func parseInvokeContentRelaxed(content []byte) (*Invoke, error) {
	offset := 0
	invokeID, present, n, err := decodeInvokeIDTLV(content[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	result := &Invoke{}
	if present {
		result.InvokeID = invokeID
	}
	if offset < len(content) && hasContextTag(content[offset:], 0, 1) {
		linkedID, present, n, err := decodeLinkedInvokeIDTLV(content[offset:])
		if err != nil {
			return nil, err
		}
		if present {
			result.LinkedID = intPtr(linkedID)
		}
		offset += n
	}

	opCode, n, err := decodeRawOpCodeTLV(content[offset:], "opcode")
	if err != nil {
		return nil, err
	}
	result.OpCode = opCode
	offset += n
	if offset < len(content) {
		result.Parameter = copyBytes(content[offset:])
	}
	return result, nil
}

func parseReturnResultContentRelaxed(content []byte) (*ReturnResult, error) {
	offset := 0
	invokeID, present, n, err := decodeInvokeIDTLV(content[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	result := &ReturnResult{}
	if present {
		result.InvokeID = invokeID
	}
	if offset < len(content) {
		_, n, _, err := ber.DecodeTLV(content[offset:])
		if err != nil {
			return nil, fmt.Errorf("decoding result: %w", err)
		}
		opCode, parameter, err := decodeResultRetRes(content[offset : offset+n])
		if err != nil {
			return nil, err
		}
		result.OpCode = &opCode
		result.Parameter = copyBytes(parameter)
		offset += n
	}
	if offset != len(content) {
		return nil, &ber.DecodeError{Offset: offset, TypeName: "ReturnResult", Cause: ber.ErrExtraData}
	}
	return result, nil
}

func parseReturnErrorContentRelaxed(content []byte) (*ReturnError, error) {
	offset := 0
	invokeID, present, n, err := decodeInvokeIDTLV(content[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	errorCode, n, err := decodeRawOpCodeTLV(content[offset:], "errcode")
	if err != nil {
		return nil, err
	}
	offset += n

	result := &ReturnError{ErrorCode: errorCode}
	if present {
		result.InvokeID = invokeID
	}
	if offset < len(content) {
		result.Parameter = copyBytes(content[offset:])
	}
	return result, nil
}

func parseRejectContentRelaxed(content []byte) (*Reject, error) {
	offset := 0
	invokeID, present, n, err := decodeInvokeIDTLV(content[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	_, n, _, err = ber.DecodeTLV(content[offset:])
	if err != nil {
		return nil, fmt.Errorf("decoding problem: %w", err)
	}
	var problem asn1tcap.OperationsRejectProblem
	if err := problem.UnmarshalBER(content[offset : offset+n]); err != nil {
		return nil, fmt.Errorf("decoding problem: %w", err)
	}
	offset += n
	if offset != len(content) {
		return nil, &ber.DecodeError{Offset: offset, TypeName: "Reject", Cause: ber.ErrExtraData}
	}

	result := &Reject{}
	if present {
		result.InvokeID = intPtr(invokeID)
	}
	switch problem.Choice {
	case asn1tcap.OperationsRejectProblemChoiceGeneral:
		result.GeneralProblem = problem.General
	case asn1tcap.OperationsRejectProblemChoiceInvoke:
		result.InvokeProblem = problem.Invoke
	case asn1tcap.OperationsRejectProblemChoiceReturnResult:
		result.ReturnResultProblem = problem.ReturnResult
	case asn1tcap.OperationsRejectProblemChoiceReturnError:
		result.ReturnErrorProblem = problem.ReturnError
	}
	return result, nil
}

func decodeInvokeIDTLV(data []byte) (int, bool, int, error) {
	if len(data) == 0 {
		return 0, false, 0, fmt.Errorf("missing invokeId")
	}
	_, n, _, err := ber.DecodeTLV(data)
	if err != nil {
		return 0, false, 0, fmt.Errorf("decoding invokeId: %w", err)
	}
	var invokeID asn1tcap.InvokeId
	if err := invokeID.UnmarshalBER(data[:n]); err != nil {
		return 0, false, 0, fmt.Errorf("decoding invokeId: %w", err)
	}
	if invokeID.Choice != asn1tcap.InvokeIdChoicePresent {
		return 0, false, n, nil
	}
	value, err := convertASN1InvokeIDToInt(invokeID.Present)
	if err != nil {
		return 0, false, 0, err
	}
	return value, true, n, nil
}

func decodeLinkedInvokeIDTLV(data []byte) (int, bool, int, error) {
	decodedTag, n, raw, err := ber.DecodeTLV(data)
	if err != nil {
		return 0, false, 0, fmt.Errorf("decoding linkedId: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific {
		return 0, false, 0, fmt.Errorf("expected linkedId context tag, got %s", decodedTag)
	}
	switch decodedTag.Number {
	case 0:
		value, present, used, err := decodeInvokeIDTLV(raw)
		if err != nil {
			return 0, false, 0, fmt.Errorf("decoding linkedId: %w", err)
		}
		if used != len(raw) {
			return 0, false, 0, &ber.DecodeError{Offset: used, TypeName: "InvokeLinkedId", Cause: ber.ErrExtraData}
		}
		return value, present, n, nil
	case 1:
		return 0, false, n, nil
	default:
		return 0, false, 0, fmt.Errorf("unknown linkedId tag %s", decodedTag)
	}
}

func decodeRawOpCodeTLV(data []byte, field string) (int64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("missing %s", field)
	}
	_, n, _, err := ber.DecodeTLV(data)
	if err != nil {
		return 0, 0, fmt.Errorf("decoding %s: %w", field, err)
	}
	value, err := decodeOpCodeFromRawValue(runtime.RawValue{Bytes: data[:n]})
	if err != nil {
		return 0, 0, fmt.Errorf("decoding %s: %w", field, err)
	}
	return value, n, nil
}

func decodeApplicationTLV(data []byte, number int, constructed bool, field string) ([]byte, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("missing %s", field)
	}
	decodedTag, n, raw, err := ber.DecodeTLV(data)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding %s: %w", field, err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != number || decodedTag.Constructed != constructed {
		return nil, 0, fmt.Errorf("expected %s tag [APPLICATION %d], got %s", field, number, decodedTag)
	}
	return raw, n, nil
}

func hasApplicationTag(data []byte, number int) bool {
	if len(data) == 0 {
		return false
	}
	decodedTag, err := ber.PeekTag(data)
	return err == nil && decodedTag.Class == tag.ClassApplication && decodedTag.Number == number
}

func hasContextTag(data []byte, numbers ...int) bool {
	if len(data) == 0 {
		return false
	}
	decodedTag, err := ber.PeekTag(data)
	if err != nil || decodedTag.Class != tag.ClassContextSpecific {
		return false
	}
	for _, number := range numbers {
		if decodedTag.Number == number {
			return true
		}
	}
	return false
}

func copyBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}
