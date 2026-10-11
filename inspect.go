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
// A failure it locates in the dialogue or component portion sets Err; limits
// are the caller's decode limits.
func inspectFailure(data []byte, opts []ber.DecodeOption, transactionOnly bool, limits ber.DecodeLimits) *ParseError {
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
		contents, indefinite := inspectedContents(data)
		children, _ := scanChildren(contents, indefinite, opts, limits)
		pe.OTID, pe.DTID = inspectedTIDs(children, pe.MessageType, opts)
		return pe
	}
	children, err := scanChildren(value, false, opts, limits)
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
	for _, data := range children.leading {
		t, _, value, _ := ber.DecodeTLV(data, opts...)
		switch t.Number {
		case 11:
			var w wire.DialoguePortion
			err := w.UnmarshalBER(data, opts...)
			var d *Dialogue
			if err == nil {
				d, err = decodeDialogue(&w, pe.MessageType, opts)
			}
			if errors.Is(err, ber.ErrResourceLimit) {
				pe.Err = err
				return pe
			}
			if err != nil {
				pe.Portion, pe.Err = PortionDialogue, err
				return pe
			}
			dialogue = d
		case 12:
			var prefix []Component
			index := 0
			for len(value) > 0 {
				ct, n, content, err := ber.DecodeTLV(value, opts...)
				if errors.Is(err, ber.ErrResourceLimit) {
					pe.Err = err
					return pe
				}
				if err != nil {
					ct, _ = ber.PeekTag(value)
					pe.Portion, pe.ComponentIndex, pe.ComponentType, pe.Err = PortionComponent, index, inspectedComponentType(ct), err
					pe.Dialogue, pe.Components = dialogue, prefix
					return pe
				}
				var c Component
				if !recognizedComponent(ct) {
					err = ErrUnrecognizedComponent
				} else {
					var w wire.Component
					if err = w.UnmarshalBER(value[:n], opts...); err == nil {
						c, err = decodeComponent(w, fmt.Sprintf("Components[%d]", index), opts)
					}
				}
				if errors.Is(err, ber.ErrResourceLimit) {
					pe.Err = err
					return pe
				}
				if err != nil {
					pe.Portion, pe.ComponentIndex, pe.ComponentType, pe.Err = PortionComponent, index, inspectedComponentType(ct), err
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
					pe.Portion, pe.Err = PortionComponent, err
					return pe
				}
			}
		}
	}
	return pe
}

// messageChildren is what inspection keeps of the immediate children of a
// message: the leading ones, their number, and each transaction ID element
// with its position (Q.774 (06/97) Table 7).
type messageChildren struct {
	leading [][]byte
	count   int
	ids     [2][]byte
	idPos   [2]int
	idCount [2]int
}

// A sound transaction portion has at most four elements (Q.773 (06/97) clause
// 3.1, Continue); inspection keeps one more to see that a message has more.
const leadingChildren = 5

func (c *messageChildren) add(child []byte) {
	if t, err := ber.PeekTag(child); err == nil && t.Class == tag.ClassApplication && (t.Number == 8 || t.Number == 9) {
		c.idCount[t.Number-8]++
		c.ids[t.Number-8], c.idPos[t.Number-8] = child, c.count
	}
	if c.count < leadingChildren {
		c.leading = append(c.leading, child)
	}
	c.count++
}

// Q.774 Table 7 permits deriving IDs before a malformed later child.
// The scan reads immediate children within the decode limits, including the
// tag of a malformed final child so duplicate IDs remain underivable.
// MaxWork bounds the octets of the children scanned, as it bounds the
// codec. Indefinite contents end at their end-of-contents indicator
// (Q.773 clause 4.1.2.3).
func scanChildren(data []byte, indefinite bool, opts []ber.DecodeOption, limits ber.DecodeLimits) (messageChildren, error) {
	var children messageChildren
	work := 0
	for len(data) > 0 {
		if indefinite && len(data) >= 2 && data[0] == 0 && data[1] == 0 {
			break
		}
		if children.count >= limits.MaxElements {
			return children, ber.ErrResourceLimit
		}
		n, err := elementLength(data, limits)
		if err != nil {
			children.add(data)
			return children, err
		}
		if work += n; work > limits.MaxWork {
			return children, ber.ErrResourceLimit
		}
		children.add(data[:n])
		data = data[n:]
	}
	return children, nil
}

// elementLength returns the length of the element at the start of data,
// within limits. A definite length is read from its header; indefinite
// contents end at the end-of-contents indicator that matches them (X.690
// (02/2021) clauses 8.1.3.6 and 8.1.5).
func elementLength(data []byte, limits ber.DecodeLimits) (int, error) {
	pos, depth, elements := 0, 0, 0
	for {
		if depth > 0 && len(data)-pos >= 2 && data[pos] == 0 && data[pos+1] == 0 {
			pos += 2
			if depth--; depth == 0 {
				return pos, nil
			}
			continue
		}
		if elements++; elements > limits.MaxElements || pos > limits.MaxWork {
			return 0, ber.ErrResourceLimit
		}
		t, tn, err := ber.DecodeTag(data[pos:])
		if err != nil {
			return 0, err
		}
		length, indefinite, ln, err := ber.DecodeLength(data[pos+tn:])
		if err != nil {
			return 0, err
		}
		pos += tn + ln
		switch {
		case indefinite && !t.Constructed:
			return 0, ber.ErrInvalidLength
		case indefinite:
			if depth++; depth > limits.MaxDepth {
				return 0, ber.ErrResourceLimit
			}
		case length > len(data)-pos:
			return 0, ber.ErrTruncated
		default:
			pos += length
		}
		if depth == 0 {
			return pos, nil
		}
	}
}

// inspectedContents returns the contents of a constructed element whose
// complete TLV cannot be decoded, as far as its header allows, and whether
// its length is indefinite.
func inspectedContents(data []byte) ([]byte, bool) {
	_, tn, err := ber.DecodeTag(data)
	if err != nil {
		return nil, false
	}
	length, indefinite, ln, err := ber.DecodeLength(data[tn:])
	if err != nil {
		return nil, false
	}
	contents := data[tn+ln:]
	if !indefinite && length < len(contents) {
		contents = contents[:length]
	}
	return contents, indefinite
}

// ITU-T Q.773 (06/97) clause 3.1 and Tables 3-7 define immediate child order.
// Transaction IDs admit the BER string forms of X.690 (02/2021) clause 8.7.
func soundTransaction(kept messageChildren, mt MessageType, opts []ber.DecodeOption) bool {
	if kept.count > len(kept.leading) {
		return false
	}
	children := kept.leading
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
func inspectedTIDs(children messageChildren, mt MessageType, opts []ber.DecodeOption) (TransactionID, TransactionID) {
	var ids [2]TransactionID
	for i := range ids {
		if children.idCount[i] != 1 {
			continue
		}
		pos := children.idPos[i]
		allowed := mt == "" || i == 0 && (mt == MessageTypeBegin || mt == MessageTypeContinue) && pos == 0 || i == 1 && (mt == MessageTypeContinue && pos == 1 || (mt == MessageTypeEnd || mt == MessageTypeAbort) && pos == 0)
		if !allowed {
			continue
		}
		t, _, value, err := ber.DecodeTLV(children.ids[i], opts...)
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
// With constraint tolerance, a value outside -128..127 that Parse accepts is
// derivable as well.
func derivableInvokeID(content []byte, opts []ber.DecodeOption) *int64 {
	t, _, value, err := ber.DecodeTLV(content, opts...)
	if err != nil || t.Class != tag.ClassUniversal || t.Number != tag.TagInteger || t.Constructed {
		return nil
	}
	n, err := ber.DecodeIntegerValue(value)
	if err != nil || (n < -128 || n > 127) && !ber.ConstraintToleranceEnabled(opts) {
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
