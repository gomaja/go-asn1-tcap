package tcap

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
)

var bigOne = big.NewInt(1)

// ITU-T Q.773 (06/97) clause 3.1: build fresh TCMessage alternatives so BER
// preservation in the codec cannot retain noncanonical transaction encodings.
func marshalMessage(m Message) ([]byte, error) {
	var mt MessageType
	var otid, dtid TransactionID
	var dialogue *Dialogue
	var components []Component
	var cause *wire.PAbortCause
	switch m := m.(type) {
	case *Begin:
		if m == nil {
			return nil, ErrNilMessage
		}
		mt, otid, dialogue, components = MessageTypeBegin, m.OTID, m.Dialogue, m.Components
	case *Continue:
		if m == nil {
			return nil, ErrNilMessage
		}
		mt, otid, dtid, dialogue, components = MessageTypeContinue, m.OTID, m.DTID, m.Dialogue, m.Components
	case *End:
		if m == nil {
			return nil, ErrNilMessage
		}
		mt, dtid, dialogue, components = MessageTypeEnd, m.DTID, m.Dialogue, m.Components
	case *Abort:
		if m == nil {
			return nil, ErrNilMessage
		}
		mt, dtid, dialogue, cause = MessageTypeAbort, m.DTID, m.Dialogue, m.PAbortCause
		// Q.773 clause 3.1, Abort-reason is a CHOICE.
		if dialogue != nil && cause != nil {
			return nil, fieldError("Dialogue", ErrAbortMultipleReasons)
		}
	case *Unidirectional:
		if m == nil {
			return nil, ErrNilMessage
		}
		mt, dialogue, components = MessageTypeUnidirectional, m.Dialogue, m.Components
	default:
		return nil, ErrNilMessage
	}
	if err := validateDialogue(dialogue, mt, true); err != nil {
		return nil, err
	}
	d, err := encodeDialogue(dialogue)
	if err != nil {
		var fe *FieldError
		if errors.As(err, &fe) {
			return nil, err
		}
		return nil, fmt.Errorf("tcap: marshal %s: %w", mt, err)
	}
	c, err := encodeComponents(components)
	if err != nil {
		return nil, err
	}
	var msg wire.TCMessage
	// Q.773 clause 4.2.1.3 and clause 3.1: leave SIZE checks to the codec,
	// including present-empty and mandatory component portions.
	switch mt {
	case MessageTypeBegin:
		msg = wire.NewTCMessageBegin(wire.Begin{Otid: wire.OrigTransactionID(slices.Clone(otid)), DialoguePortion: d, Components: c})
	case MessageTypeContinue:
		msg = wire.NewTCMessageContinue(wire.Continue{Otid: wire.OrigTransactionID(slices.Clone(otid)), Dtid: wire.DestTransactionID(slices.Clone(dtid)), DialoguePortion: d, Components: c})
	case MessageTypeEnd:
		msg = wire.NewTCMessageEnd(wire.End{Dtid: wire.DestTransactionID(slices.Clone(dtid)), DialoguePortion: d, Components: c})
	case MessageTypeUnidirectional:
		if c == nil {
			c = &wire.ComponentPortion{}
		}
		msg = wire.NewTCMessageUnidirectional(wire.Unidirectional{DialoguePortion: d, Components: *c})
	case MessageTypeAbort:
		var reason *wire.AbortReason
		if cause != nil {
			r := wire.NewAbortReasonPAbortCause(*cause)
			reason = &r
		}
		if d != nil {
			r := wire.NewAbortReasonUAbortCause(*d)
			reason = &r
		}
		msg = wire.NewTCMessageAbort(wire.Abort{Dtid: wire.DestTransactionID(slices.Clone(dtid)), Reason: reason})
	}
	out, err := msg.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("tcap: marshal %s: %w", mt, err)
	}
	return out, nil
}

// Q.773 clause 3.1 and Annex A map the ROS alternatives to components.
func encodeComponents(cs []Component) (*wire.ComponentPortion, error) {
	if cs == nil {
		return nil, nil
	}
	out := &wire.ComponentPortion{Values: make([]wire.Component, len(cs))}
	for i, c := range cs {
		path := fmt.Sprintf("Components[%d]", i)
		count := set(c.Invoke != nil) + set(c.ReturnResultLast != nil) + set(c.ReturnResultNotLast != nil) + set(c.ReturnError != nil) + set(c.Reject != nil)
		if err := alternative(count, ErrComponentNoAlternative, ErrComponentMultipleAlternatives); err != nil {
			return nil, fieldError(path, err)
		}
		var ros wire.ROS
		switch {
		case c.Invoke != nil:
			v := c.Invoke
			p := path + ".Invoke"
			w := wire.Invoke{InvokeId: wire.NewTCInvokeIdSetPresentInt64(v.InvokeID)}
			if v.LinkedID != nil {
				// Q.773 Table 20: [0] IMPLICIT INTEGER, not an explicit wrapper.
				l := wire.NewInvokeLinkedIdPresentInt64(*v.LinkedID)
				w.LinkedId = &l
			}
			code, err := encodeCode(v.OpCode, p+".OpCode")
			if err != nil {
				return nil, err
			}
			w.Opcode = code
			if v.Parameter != nil {
				w.Argument = &runtime.RawValue{Bytes: slices.Clone(v.Parameter)}
			}
			ros = wire.NewROSInvoke(w)
		case c.ReturnResultLast != nil || c.ReturnResultNotLast != nil:
			v, name := c.ReturnResultLast, ".ReturnResultLast"
			if v == nil {
				v, name = c.ReturnResultNotLast, ".ReturnResultNotLast"
			}
			w, err := encodeResult(v, path+name)
			if err != nil {
				return nil, err
			}
			if c.ReturnResultNotLast != nil {
				out.Values[i] = wire.NewComponentReturnResultNotLast(w)
				continue
			}
			ros = wire.NewROSReturnResult(w)
		case c.ReturnError != nil:
			v, p := c.ReturnError, path+".ReturnError"
			code, err := encodeCode(v.ErrorCode, p+".ErrorCode")
			if err != nil {
				return nil, err
			}
			w := wire.ReturnError{InvokeId: wire.NewInvokeIdPresentInt64(v.InvokeID), Errcode: code}
			if v.Parameter != nil {
				w.Parameter = &runtime.RawValue{Bytes: slices.Clone(v.Parameter)}
			}
			ros = wire.NewROSReturnError(w)
		case c.Reject != nil:
			v, p := c.Reject, path+".Reject"
			id := wire.NewInvokeIdAbsent(struct{}{})
			if v.InvokeID != nil {
				id = wire.NewInvokeIdPresentInt64(*v.InvokeID)
			}
			problem, err := encodeProblem(v.Problem, p+".Problem")
			if err != nil {
				return nil, err
			}
			ros = wire.NewROSReject(wire.Reject{InvokeId: id, Problem: problem})
		}
		out.Values[i] = wire.NewComponentBasicROS(ros)
	}
	return out, nil
}

// Q.773 Table 16 note b makes both fields mandatory when result is present.
func encodeResult(v *ReturnResult, path string) (wire.ReturnResult, error) {
	w := wire.ReturnResult{InvokeId: wire.NewInvokeIdPresentInt64(v.InvokeID)}
	if v.Result != nil {
		code, err := encodeCode(v.Result.OpCode, path+".Result.OpCode")
		if err != nil {
			return w, err
		}
		w.Result = &wire.ReturnResultResult{Opcode: code, Result: runtime.RawValue{Bytes: slices.Clone(v.Result.Parameter)}}
	}
	return w, nil
}

// Q.773 clauses 4.2.2.3 and 4.2.2.5 use the X.880 Code CHOICE.
func encodeCode(v Code, path string) (wire.Code, error) {
	switch v := v.(type) {
	case *LocalCode:
		if v != nil {
			return encodeCode(*v, path)
		}
		return wire.Code{}, fieldError(path, ErrCodeNoAlternative)
	case *GlobalCode:
		if v != nil {
			return encodeCode(*v, path)
		}
		return wire.Code{}, fieldError(path, ErrCodeNoAlternative)
	case LocalCode:
		return wire.NewCodeLocal(big.NewInt(int64(v))), nil
	case GlobalCode:
		arcs, err := parseOID(string(v))
		if err != nil {
			return wire.Code{}, fieldError(path, err)
		}
		return wire.NewCodeGlobal(arcs), nil
	default:
		return wire.Code{}, fieldError(path, ErrCodeNoAlternative)
	}
}

// Q.773 clause 4.2.2.6 requires one problem alternative.
func encodeProblem(v Problem, path string) (wire.RejectProblemChoice, error) {
	count := set(v.General != nil) + set(v.Invoke != nil) + set(v.ReturnResult != nil) + set(v.ReturnError != nil)
	if err := alternative(count, ErrProblemNoAlternative, ErrProblemMultipleAlternatives); err != nil {
		return wire.RejectProblemChoice{}, fieldError(path, err)
	}
	switch {
	case v.General != nil:
		return wire.NewRejectProblemChoiceGeneral(*v.General), nil
	case v.Invoke != nil:
		return wire.NewRejectProblemChoiceInvoke(*v.Invoke), nil
	case v.ReturnResult != nil:
		return wire.NewRejectProblemChoiceReturnResult(*v.ReturnResult), nil
	default:
		return wire.NewRejectProblemChoiceReturnError(*v.ReturnError), nil
	}
}
