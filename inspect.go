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
	// go-asn1 validates the whole message and locates its first failure
	// (ber.ElementError). Once the decode limits are exceeded, IDs are taken
	// only from the top-level elements examined before that location.
	validation := ber.ValidateBERElement(data, opts...)
	if transactionOnly || errors.Is(validation, ber.ErrResourceLimit) {
		contents, _ := inspectedContents(data)
		var children messageChildren
		for i := validatedPrefix(validation); i > 0 && len(contents) > 0; i-- {
			_, n, _, err := ber.DecodeTLV(contents, opts...)
			if err != nil {
				break
			}
			children.add(contents[:n])
			contents = contents[n:]
		}
		pe.OTID, pe.DTID = inspectedTIDs(children, pe.MessageType, true, opts)
		if !transactionOnly {
			pe.Err = joinErrors(pe.Err, firstLimit(validation))
		}
		return pe
	}
	_, n, value, err := inspectTLV(data, opts, limits, true)
	if err != nil {
		// Q.774 Table 7: the leading IDs may still be derivable when a later
		// part of the message cannot be decoded.
		contents, indefinite := inspectedContents(data)
		children, scanErr := scanChildren(contents, indefinite, limits)
		limit := firstLimit(err, scanErr)
		if limit != nil {
			children = children.prefix(validLeading(children.leading, opts))
		}
		pe.OTID, pe.DTID = inspectedTIDs(children, pe.MessageType, limit != nil, opts)
		if limit != nil {
			pe.Err = joinErrors(pe.Err, limit)
		}
		return pe
	}
	children, err := scanChildren(value, false, limits)
	limit := firstLimit(err)
	if limit != nil {
		children = children.prefix(validLeading(children.leading, opts))
	}
	pe.OTID, pe.DTID = inspectedTIDs(children, pe.MessageType, limit != nil, opts)
	if !transactionOnly && limit != nil {
		pe.Err = joinErrors(pe.Err, limit)
	}
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
		t, _, value, _ := inspectTLV(data, opts, limits, false)
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
				ct, n, content, err := inspectTLV(value, opts, limits, false)
				if errors.Is(err, ber.ErrResourceLimit) {
					pe.Err = err
					return pe
				}
				if err != nil {
					// The first element of a component that cannot be
					// delimited may still be a complete invoke ID.
					ct, _ = ber.PeekTag(value)
					pe.Portion, pe.ComponentIndex, pe.ComponentType, pe.Err = PortionComponent, index, inspectedComponentType(ct), err
					if ct.Constructed {
						contents, _ := inspectedContents(value)
						pe.InvokeID = derivableInvokeID(contents, opts)
					}
					pe.Dialogue, pe.Components = dialogue, prefix
					return pe
				}
				var c Component
				if !recognizedComponent(ct) {
					err = ErrUnrecognizedComponent
				} else {
					var w wire.Component
					if err = w.UnmarshalBER(value[:n], opts...); err == nil {
						c, err = decodeComponent(componentValue(w), fmt.Sprintf("Components[%d]", index), opts)
					}
				}
				if errors.Is(err, ber.ErrResourceLimit) {
					pe.Err = err
					return pe
				}
				if err != nil {
					pe.Portion, pe.ComponentIndex, pe.ComponentType, pe.Err = PortionComponent, index, inspectedComponentType(ct), err
					if ct.Constructed {
						pe.InvokeID = derivableInvokeID(content, opts)
					}
					pe.Dialogue, pe.Components = dialogue, prefix
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

// prefix keeps only the first n leading children, the elements from which
// IDs may be taken at their positions once the decode limits are exceeded.
func (c messageChildren) prefix(n int) messageChildren {
	c.leading = c.leading[:min(n, len(c.leading))]
	return c
}

// validatedPrefix returns the number of top-level elements of a message that
// ber.ValidateBERElement examined within the limits before the element at
// which err, its result, locates a failure. Without a location there are none;
// go-asn1 locates a MaxWork failure at the root: https://github.com/gomaja/go-asn1/issues/155.
func validatedPrefix(err error) int {
	var located *ber.ElementError
	if !errors.As(err, &located) || len(located.ChildIndexes()) == 0 {
		return 0
	}
	return located.ChildIndexes()[0]
}

// validLeading returns how many of the leading children, in order, are valid
// within the decode limits, as ber.ValidateBERElement checks them. It bounds
// the IDs taken at their positions when the inspection meets a limit itself.
func validLeading(leading [][]byte, opts []ber.DecodeOption) int {
	for i, child := range leading {
		if ber.ValidateBERElement(child, opts...) != nil {
			return i
		}
	}
	return len(leading)
}

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
// Indefinite contents end at their end-of-contents indicator (Q.773 clause
// 4.1.2.3).
func scanChildren(data []byte, indefinite bool, limits ber.DecodeLimits) (messageChildren, error) {
	var children messageChildren
	budget := scanBudget{limits: limits, elements: 1}
	for len(data) > 0 {
		if indefinite && len(data) >= 2 && data[0] == 0 && data[1] == 0 {
			break
		}
		n, err := budget.elementLength(data)
		if errors.Is(err, ber.ErrResourceLimit) {
			return children, err
		}
		if err != nil {
			children.add(data)
			return children, err
		}
		children.add(data[:n])
		data = data[n:]
	}
	return children, nil
}

// scanBudget holds the decode limits for one scan of a message and what the
// scan has used of them. They bound its cost: MaxElements counts the message
// and every element read in it, MaxDepth the levels of nesting from the
// message, and MaxWork the octets of the elements read.
type scanBudget struct {
	limits         ber.DecodeLimits
	elements, work int
	messageRoot    bool
}

// elementLength returns the length of the element at the start of data. A
// definite length is read from its header; indefinite contents end at the
// end-of-contents indicator that matches them (X.690 (02/2021) clauses
// 8.1.3.6 and 8.1.5). As in ber.DecodeTLV, the elements inside are only
// delimited, so a malformed one is left to the decoding of its component.
func (b *scanBudget) elementLength(data []byte) (int, error) {
	pos, depth := 0, 0
	for {
		if depth > 0 && len(data)-pos >= 2 && data[pos] == 0 && data[pos+1] == 0 {
			pos += 2
			if depth--; depth == 0 {
				break
			}
			continue
		}
		if b.elements++; b.elements > b.limits.MaxElements || b.work+pos >= b.limits.MaxWork {
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
		case indefinite && !t.Constructed && depth == 0:
			// X.690 clause 8.1.3.2 a): a primitive encoding has a definite length.
			return 0, ber.ErrInvalidLength
		case indefinite:
			ancestors := 1
			if b.messageRoot {
				ancestors = 0
			}
			if depth++; ancestors+depth > b.limits.MaxDepth {
				return 0, ber.ErrResourceLimit
			}
		case length > len(data)-pos:
			return 0, ber.ErrTruncated
		default:
			pos += length
		}
		if depth == 0 {
			break
		}
	}
	if b.work += pos; b.work > b.limits.MaxWork {
		return 0, ber.ErrResourceLimit
	}
	return pos, nil
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
		t, err := ber.PeekTag(children[pos])
		if err != nil || t.Class != tag.ClassApplication || t.Number != number {
			return false
		}
		id, ok := transactionIDValue(children[pos], opts)
		if !ok || len(id) < 1 && !ber.ConstraintToleranceEnabled(opts) {
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
	t, err := ber.PeekTag(data)
	return err == nil && t.Class == tag.ClassApplication && t.Constructed && t.Number == number
}

// Q.774 Table 7 derives IDs only at Q.773 clause 3.1 positions; UNKNOWN
// messages admit unique first-level IDs. Duplicates are not derivable. When
// the message exceeds the decode limits, children holds only the elements
// examined within them, the IDs at their positions are taken without looking
// for repetitions, and an UNKNOWN message has none.
func inspectedTIDs(children messageChildren, mt MessageType, limited bool, opts []ber.DecodeOption) (TransactionID, TransactionID) {
	var ids [2]TransactionID
	for i := range ids {
		var element []byte
		if limited {
			if pos := tidPosition(mt, i); pos >= 0 && pos < len(children.leading) {
				element = children.leading[pos]
			}
		} else if children.idCount[i] == 1 && (mt == "" || tidPosition(mt, i) == children.idPos[i]) {
			element = children.ids[i]
		}
		if element == nil {
			continue
		}
		t, err := ber.PeekTag(element)
		if err != nil || t.Class != tag.ClassApplication || t.Number != 8+i {
			continue
		}
		if id, ok := transactionIDValue(element, opts); ok {
			ids[i] = derivableTID(id, ber.ConstraintToleranceEnabled(opts))
		}
	}
	return ids[0], ids[1]
}

// tidPosition returns the position that Q.773 clause 3.1 gives the OTID
// (i is 0) or the DTID (i is 1) among the elements of a message of type mt,
// or -1.
func tidPosition(mt MessageType, i int) int {
	switch {
	case i == 0 && (mt == MessageTypeBegin || mt == MessageTypeContinue):
		return 0
	case i == 1 && mt == MessageTypeContinue:
		return 1
	case i == 1 && (mt == MessageTypeEnd || mt == MessageTypeAbort):
		return 0
	}
	return -1
}

// transactionIDValue decodes the BER string forms in ITU-T X.690
// (02/2021) clause 8.7 with the caller's options. Q.773 clause 3.1 limits
// the resulting transaction ID to 1..4 octets unless constraints are tolerated.
func transactionIDValue(element []byte, opts []ber.DecodeOption) ([]byte, bool) {
	t, n, value, err := ber.DecodeTLV(element, opts...)
	if err != nil || n != len(element) {
		return nil, false
	}
	id, err := ber.DecodeImplicitOctetStringValue(t.Constructed, value, opts...)
	if err != nil {
		return nil, false
	}
	if !ber.ConstraintToleranceEnabled(opts) && (len(id) < 1 || len(id) > 4) {
		return nil, false
	}
	return id, true
}

// inspectTLV delimits malformed indefinite children so Q.774 Table 5 can
// locate the first failing component. DecodeTLV checks nested universal forms
// only in indefinite values: https://github.com/gomaja/go-asn1/issues/152.
// This fallback goes once DecodeTLV delimits both length forms alike.
func inspectTLV(data []byte, opts []ber.DecodeOption, limits ber.DecodeLimits, messageRoot bool) (tag.Tag, int, []byte, error) {
	t, n, value, err := ber.DecodeTLV(data, opts...)
	if err == nil || errors.Is(err, ber.ErrResourceLimit) {
		return t, n, value, err
	}
	n, scanErr := (&scanBudget{limits: limits, messageRoot: messageRoot}).elementLength(data)
	if scanErr != nil {
		return t, 0, nil, err
	}
	t, err = ber.PeekTag(data)
	if err != nil {
		return t, 0, nil, err
	}
	value, indefinite := inspectedContents(data[:n])
	if indefinite {
		value = value[:len(value)-2]
	}
	return t, n, value, nil
}

// firstLimit returns the first of errs that is a decode limit, or nil.
func firstLimit(errs ...error) error {
	for _, err := range errs {
		if errors.Is(err, ber.ErrResourceLimit) {
			return err
		}
	}
	return nil
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

// Q.773 clause 4.2.2.2 and Q.774 Table 5: derive only a valid first INTEGER
// of a constructed component (Q.773 Table 19); content is its contents.
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
