package tcap

import (
	"errors"
	"fmt"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// ITU-T Q.774 (06/97) Tables 5 and 7: inspection derives abnormal-procedure
// context after a failure. It never accepts a message or publishes reports.
func inspectFailure(data []byte, opts []ber.DecodeOption, transactionOnly bool, maxElements int) *ParseError {
	opts, _ = ber.StageDecodeReports(opts)
	pe := &ParseError{Portion: PortionTransaction, ComponentIndex: -1}
	t, err := ber.PeekTag(data)
	if err != nil {
		return pe
	}
	pe.MessageType = inspectedMessageType(t)
	if pe.MessageType == "" {
		pe.Err = ErrUnrecognizedMessageType
	}
	// Q.773 Table 8: a message is constructed; a primitive has no children.
	if !t.Constructed {
		return pe
	}
	_, n, value, err := ber.DecodeTLV(data, opts...)
	if err != nil {
		// Q.774 Table 7: the leading IDs may still be derivable when a later
		// part of the message cannot be decoded.
		children, _ := inspectedChildren(inspectedContents(data), opts, maxElements)
		pe.OTID, pe.DTID = inspectedTIDs(children, pe.MessageType, opts)
		return pe
	}
	children, err := inspectedChildren(value, opts, maxElements)
	pe.OTID, pe.DTID = inspectedTIDs(children, pe.MessageType, opts)
	if err != nil {
		return pe
	}
	// Q.773 clause 3.1 and Tables 3-7 establish the transaction portion
	// before Q.774 clause 3.2.2.2 permits inspection of the other portions.
	if transactionOnly || pe.MessageType == "" || n != len(data) || !soundTransaction(children, pe.MessageType, opts) {
		return pe
	}
	var dialogue *Dialogue
	for _, data := range children {
		t, _, value, _ := ber.DecodeTLV(data, opts...)
		switch t.Number {
		case 11:
			var w wire.DialoguePortion
			if err := w.UnmarshalBER(data, opts...); err != nil {
				if !errors.Is(err, ber.ErrResourceLimit) {
					pe.Portion = PortionDialogue
				}
				return pe
			}
			d, err := decodeDialogue(&w, pe.MessageType, opts)
			if errors.Is(err, ber.ErrResourceLimit) {
				return pe
			}
			if err != nil {
				// The codec does not decode the dialogue PDU, so this is the
				// failure the dialogue portion reports.
				pe.Portion, pe.Err = PortionDialogue, joinErrors(pe.Err, err)
				return pe
			}
			dialogue = d
		case 12:
			var prefix []Component
			index := 0
			for len(value) > 0 {
				ct, n, content, err := ber.DecodeTLV(value, opts...)
				if errors.Is(err, ber.ErrResourceLimit) {
					return pe
				}
				if err != nil {
					ct, _ = ber.PeekTag(value)
					pe.Portion, pe.ComponentIndex, pe.ComponentType, pe.Dialogue, pe.Components = PortionComponent, index, inspectedComponentType(ct), dialogue, prefix
					return pe
				}
				var c Component
				if !recognizedComponent(ct) {
					err = ErrUnrecognizedComponent
					pe.Err = joinErrors(pe.Err, err)
				} else {
					var w wire.Component
					err = w.UnmarshalBER(value[:n], opts...)
					if err == nil {
						// A receiver rule rejects a component the codec decoded;
						// report that failure, not a later one of the codec.
						if c, err = decodeComponent(w, fmt.Sprintf("Components[%d]", index), opts); err != nil {
							pe.Err = joinErrors(pe.Err, err)
						}
					}
				}
				if errors.Is(err, ber.ErrResourceLimit) {
					return pe
				}
				if err != nil {
					pe.Portion, pe.ComponentIndex, pe.ComponentType = PortionComponent, index, inspectedComponentType(ct)
					pe.InvokeID, pe.Dialogue, pe.Components = derivableInvokeID(content, opts), dialogue, prefix
					return pe
				}
				prefix = append(prefix, c)
				value = value[n:]
				index++
			}
			// Q.773 clause 3.1: ComponentPortion has SIZE (1..MAX).
			if index == 0 {
				if _, err := wire.UnmarshalBERComponentPortion(data, opts...); err != nil {
					pe.Portion = PortionComponent
					return pe
				}
			}
		}
	}
	return pe
}

// Q.774 Table 7 permits deriving IDs before a malformed later child.
// The scan retains immediate children within the decode limits, including
// the tag of a malformed final child so duplicate IDs remain underivable.
func inspectedChildren(data []byte, opts []ber.DecodeOption, maxElements int) ([][]byte, error) {
	var children [][]byte
	for len(data) > 0 {
		if len(children) >= maxElements {
			return children, ber.ErrResourceLimit
		}
		_, n, _, err := ber.DecodeTLV(data, opts...)
		if err != nil {
			children = append(children, data)
			return children, err
		}
		children = append(children, data[:n])
		data = data[n:]
	}
	return children, nil
}

// inspectedContents returns the contents of a constructed element whose
// complete TLV cannot be decoded, as far as its header allows.
func inspectedContents(data []byte) []byte {
	_, tn, err := ber.DecodeTag(data)
	if err != nil {
		return nil
	}
	length, indefinite, ln, err := ber.DecodeLength(data[tn:])
	if err != nil {
		return nil
	}
	contents := data[tn+ln:]
	if !indefinite && length < len(contents) {
		contents = contents[:length]
	}
	return contents
}

// ITU-T Q.773 (06/97) clause 3.1 and Tables 3-7 define immediate child order.
// Transaction IDs admit the BER string forms of X.690 (02/2021) clause 8.7.
func soundTransaction(children [][]byte, mt MessageType, opts []ber.DecodeOption) bool {
	var required []int
	switch mt {
	case MessageTypeBegin:
		required = []int{8}
	case MessageTypeContinue:
		required = []int{8, 9}
	case MessageTypeEnd, MessageTypeAbort:
		required = []int{9}
	}
	pos := 0
	for _, number := range required {
		if pos >= len(children) {
			return false
		}
		t, _, value, err := ber.DecodeTLV(children[pos], opts...)
		if err != nil || t.Class != tag.ClassApplication || t.Number != number {
			return false
		}
		id, err := ber.DecodeImplicitOctetStringValue(t.Constructed, value, opts...)
		if err != nil || (len(id) < 1 || len(id) > 4) && !ber.ConstraintToleranceEnabled(opts) {
			return false
		}
		pos++
	}
	if mt == MessageTypeAbort {
		if pos == len(children) {
			return true
		}
		if pos+1 != len(children) {
			return false
		}
		if applicationChild(children[pos], 11, opts) {
			return true
		}
		var reason wire.AbortReason
		return reason.UnmarshalBER(children[pos], opts...) == nil
	}
	if pos < len(children) && applicationChild(children[pos], 11, opts) {
		pos++
	}
	if pos < len(children) && applicationChild(children[pos], 12, opts) {
		pos++
	} else if mt == MessageTypeUnidirectional {
		return false
	}
	return pos == len(children)
}

func applicationChild(data []byte, number int, opts []ber.DecodeOption) bool {
	t, _, _, err := ber.DecodeTLV(data, opts...)
	return err == nil && t.Class == tag.ClassApplication && t.Constructed && t.Number == number
}

// Q.774 Table 7 derives IDs only at Q.773 clause 3.1 positions; UNKNOWN
// messages admit unique first-level IDs. Duplicates are not derivable.
func inspectedTIDs(children [][]byte, mt MessageType, opts []ber.DecodeOption) (TransactionID, TransactionID) {
	positions := [2]int{-1, -1}
	counts := [2]int{}
	for i, data := range children {
		t, err := ber.PeekTag(data)
		if err == nil && t.Class == tag.ClassApplication && (t.Number == 8 || t.Number == 9) {
			counts[t.Number-8]++
			positions[t.Number-8] = i
		}
	}
	var ids [2]TransactionID
	for i, pos := range positions {
		if counts[i] != 1 {
			continue
		}
		allowed := mt == "" || i == 0 && (mt == MessageTypeBegin || mt == MessageTypeContinue) && pos == 0 || i == 1 && (mt == MessageTypeContinue && pos == 1 || (mt == MessageTypeEnd || mt == MessageTypeAbort) && pos == 0)
		if !allowed {
			continue
		}
		t, _, value, err := ber.DecodeTLV(children[pos], opts...)
		if err != nil {
			continue
		}
		if id, err := ber.DecodeImplicitOctetStringValue(t.Constructed, value, opts...); err == nil {
			ids[i] = derivableTID(id, ber.ConstraintToleranceEnabled(opts))
		}
	}
	return ids[0], ids[1]
}

// Q.773 Table 8 requires constructed APPLICATION message tags.
func inspectedMessageType(t tag.Tag) MessageType {
	if t.Class != tag.ClassApplication || !t.Constructed {
		return ""
	}
	switch t.Number {
	case 1:
		return MessageTypeUnidirectional
	case 2:
		return MessageTypeBegin
	case 4:
		return MessageTypeEnd
	case 5:
		return MessageTypeContinue
	case 7:
		return MessageTypeAbort
	}
	return ""
}

// Q.773 Table 19 assigns constructed context-specific component tags.
func recognizedComponent(t tag.Tag) bool {
	return inspectedComponentType(t) != ""
}

func inspectedComponentType(t tag.Tag) ComponentType {
	if t.Class != tag.ClassContextSpecific || !t.Constructed {
		return ""
	}
	switch t.Number {
	case 1:
		return ComponentTypeInvoke
	case 2:
		return ComponentTypeReturnResultLast
	case 3:
		return ComponentTypeReturnError
	case 4:
		return ComponentTypeReject
	case 7:
		return ComponentTypeReturnResultNotLast
	}
	return ""
}

// Q.773 clause 4.2.2.2 and Q.774 Table 5: derive only a valid first INTEGER.
func derivableInvokeID(content []byte, opts []ber.DecodeOption) *int64 {
	t, _, value, err := ber.DecodeTLV(content, opts...)
	if err != nil || t.Class != tag.ClassUniversal || t.Number != tag.TagInteger || t.Constructed {
		return nil
	}
	n, err := ber.DecodeIntegerValue(value)
	if err != nil || n < -128 || n > 127 {
		return nil
	}
	return &n
}

func inspectComponent(data []byte, index int, opts []ber.DecodeOption) (*int64, ComponentType) {
	if index < 0 {
		return nil, ""
	}
	_, _, rest, err := ber.DecodeTLV(data, opts...)
	if err != nil {
		return nil, ""
	}
	for len(rest) > 0 {
		t, n, value, err := ber.DecodeTLV(rest, opts...)
		if err != nil {
			return nil, ""
		}
		if t.Class == tag.ClassApplication && t.Number == 12 {
			for i := 0; len(value) > 0; i++ {
				t, n, content, err := ber.DecodeTLV(value, opts...)
				if err != nil {
					return nil, ""
				}
				if i == index {
					return derivableInvokeID(content, opts), inspectedComponentType(t)
				}
				value = value[n:]
			}
			return nil, ""
		}
		rest = rest[n:]
	}
	return nil, ""
}
