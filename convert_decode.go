package tcap

import (
	"math/big"
	"slices"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// ITU-T Q.773 (06/97) clause 3.1: retain absent portions and copy owned data.
func decodeMessage(w *wire.TCMessage) (Message, *ParseError) {
	var mt MessageType
	var otid, dtid TransactionID
	var dp *wire.DialoguePortion
	var cp *wire.ComponentPortion
	var cause *wire.PAbortCause
	switch w.Choice {
	case wire.TCMessageChoiceBegin:
		mt, otid, dp, cp = MessageTypeBegin, TransactionID(w.Begin.Otid), w.Begin.DialoguePortion, w.Begin.Components
	case wire.TCMessageChoiceContinue:
		mt, otid, dtid, dp, cp = MessageTypeContinue, TransactionID(w.Continue.Otid), TransactionID(w.Continue.Dtid), w.Continue.DialoguePortion, w.Continue.Components
	case wire.TCMessageChoiceEnd:
		mt, dtid, dp, cp = MessageTypeEnd, TransactionID(w.End.Dtid), w.End.DialoguePortion, w.End.Components
	case wire.TCMessageChoiceUnidirectional:
		mt, dp, cp = MessageTypeUnidirectional, w.Unidirectional.DialoguePortion, &w.Unidirectional.Components
	case wire.TCMessageChoiceAbort:
		mt, dtid = MessageTypeAbort, TransactionID(w.Abort.Dtid)
		if r := w.Abort.Reason; r != nil {
			cause, dp = clonePointer(r.PAbortCause), r.UAbortCause
		}
	default:
		return nil, &ParseError{Portion: PortionTransaction, ComponentIndex: -1, Err: ErrUnrecognizedMessageType}
	}
	pe := &ParseError{MessageType: mt, ComponentIndex: -1}
	if mt == MessageTypeBegin || mt == MessageTypeContinue {
		pe.OTID = append(TransactionID{}, otid...)
	}
	if mt == MessageTypeContinue || mt == MessageTypeEnd || mt == MessageTypeAbort {
		pe.DTID = append(TransactionID{}, dtid...)
	}
	d, err := decodeDialogue(dp, mt)
	if err != nil {
		pe.Portion, pe.Err = PortionDialogue, err
		return nil, pe
	}
	c, index, err := decodeComponents(cp)
	if err != nil {
		if len(c) == 0 {
			c = nil
		}
		pe.Portion, pe.ComponentIndex, pe.Dialogue, pe.Components, pe.Err = PortionComponent, index, d, c, err
		return nil, pe
	}
	otid, dtid = slices.Clone(otid), slices.Clone(dtid)
	switch mt {
	case MessageTypeBegin:
		return &Begin{OTID: otid, Dialogue: d, Components: c}, nil
	case MessageTypeContinue:
		return &Continue{OTID: otid, DTID: dtid, Dialogue: d, Components: c}, nil
	case MessageTypeEnd:
		return &End{DTID: dtid, Dialogue: d, Components: c}, nil
	case MessageTypeAbort:
		return &Abort{DTID: dtid, Dialogue: d, PAbortCause: cause}, nil
	default:
		return &Unidirectional{Dialogue: d, Components: c}, nil
	}
}

func decodeComponents(cp *wire.ComponentPortion) ([]Component, int, error) {
	if cp == nil {
		return nil, -1, nil
	}
	out := make([]Component, 0, len(cp.Values))
	for i, c := range cp.Values {
		v, err := decodeComponent(c)
		if err != nil {
			return out, i, err
		}
		out = append(out, v)
	}
	return out, -1, nil
}

// decodeComponentID retains only IDs that the public int64 model can represent.
// The codec enforces ITU-T Q.773 (06/97) clause 4.2.2.2 before conversion.
func decodeComponentID(v *big.Int) (int64, error) {
	if v == nil {
		return 0, ErrMissingInvokeID
	}
	if !v.IsInt64() {
		return 0, ErrUnrepresentableValue
	}
	return v.Int64(), nil
}

func decodeComponent(c wire.Component) (Component, error) {
	var out Component
	if c.ReturnResultNotLast != nil {
		v, err := decodeResult(c.ReturnResultNotLast)
		out.ReturnResultNotLast = v
		return out, err
	}
	if c.BasicROS == nil {
		return out, ErrUnrecognizedComponent
	}
	r := c.BasicROS
	switch {
	case r.Invoke != nil:
		w := r.Invoke
		id, err := decodeComponentID(w.InvokeId.Present)
		if err != nil {
			return out, err
		}
		v := &Invoke{InvokeID: id}
		if w.LinkedId != nil {
			// Q.773 Table 20 defines only [0] IMPLICIT INTEGER for linked IDs.
			if w.LinkedId.Present == nil {
				return out, ErrInvalidLinkedID
			}
			linked, err := decodeComponentID(w.LinkedId.Present)
			if err != nil {
				return out, err
			}
			v.LinkedID = &linked
		}
		code, err := decodeCode(w.Opcode)
		if err != nil {
			return out, err
		}
		v.OpCode = code
		if w.Argument != nil {
			v.Parameter = slices.Clone(w.Argument.Bytes)
		}
		out.Invoke = v
	case r.ReturnResult != nil:
		v, err := decodeResult(r.ReturnResult)
		if err != nil {
			return out, err
		}
		out.ReturnResultLast = v
	case r.ReturnError != nil:
		w := r.ReturnError
		id, err := decodeComponentID(w.InvokeId.Present)
		if err != nil {
			return out, err
		}
		code, err := decodeCode(w.Errcode)
		if err != nil {
			return out, err
		}
		v := &ReturnError{InvokeID: id, ErrorCode: code}
		if w.Parameter != nil {
			v.Parameter = slices.Clone(w.Parameter.Bytes)
		}
		out.ReturnError = v
	case r.Reject != nil:
		w := r.Reject
		v := &Reject{Problem: Problem{General: clonePointer(w.Problem.General), Invoke: clonePointer(w.Problem.Invoke), ReturnResult: clonePointer(w.Problem.ReturnResult), ReturnError: clonePointer(w.Problem.ReturnError)}}
		// Q.773 Table 18 permits NULL only for a Reject invoke ID.
		if w.InvokeId.Present != nil {
			id, err := decodeComponentID(w.InvokeId.Present)
			if err != nil {
				return out, err
			}
			v.InvokeID = &id
		}
		out.Reject = v
	default:
		return out, ErrUnrecognizedComponent
	}
	return out, nil
}

func decodeResult(w *wire.ReturnResult) (*ReturnResult, error) {
	id, err := decodeComponentID(w.InvokeId.Present)
	if err != nil {
		return nil, err
	}
	v := &ReturnResult{InvokeID: id}
	if w.Result != nil {
		code, err := decodeCode(w.Result.Opcode)
		if err != nil {
			return nil, err
		}
		v.Result = &Result{OpCode: code, Parameter: slices.Clone(w.Result.Result.Bytes)}
	}
	return v, nil
}

// Q.773 clauses 4.2.2.3 and 4.2.2.5: local codes are arbitrary INTEGERs;
// the public representation admits only int64 values.
func decodeCode(w wire.Code) (Code, error) {
	if w.Local != nil {
		if !w.Local.IsInt64() {
			return nil, ErrUnrepresentableValue
		}
		return LocalCode(w.Local.Int64()), nil
	}
	oid, err := decodeOID(*w.Global)
	if err != nil {
		return nil, err
	}
	return GlobalCode(oid), nil
}
