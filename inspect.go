package tcap

import (
	"errors"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
)

// ITU-T Q.774 (06/97) Tables 5 and 7: inspection derives abnormal-procedure
// context after a failure. It never accepts a message or publishes reports.
// A failure it locates in the dialogue or component portion sets Err; limits
// are the caller's decode limits; failure is the codec's.
func inspectFailure(data []byte, opts []ber.DecodeOption, transactionOnly bool, limits ber.DecodeLimits, failure error) *ParseError {
	opts, _ = ber.StageDecodeReports(opts)
	pe := &ParseError{Portion: PortionTransaction, ComponentIndex: -1,
		pAbortCause: PAbortCauseBadlyFormattedTransactionPortion, pAbortCauseSet: true}
	var decoded *wire.DecodeError
	var prefix wire.TransactionPrefix
	if errors.As(failure, &decoded) {
		prefix = decoded.Prefix
	}
	var idCount [2]int
	defer func() {
		if decoded != nil {
			decodeFailureIDs(pe, decoded, idCount)
		}
	}()
	t, err := ber.PeekTag(data)
	if err != nil {
		return pe
	}
	var validation error
	defer func() {
		// Q.774 (06/97) Figure A.3 sheet 1 checks message type first.
		// Q.773 (06/97) Table 8 defines the full constructed message tags;
		// their primitive forms are unrecognized, as in Err and MessageType.
		switch {
		case inspectedMessageType(t) == "":
			pe.pAbortCause = PAbortCauseUnrecognizedMessageType
		case errors.Is(failure, ber.ErrResourceLimit):
			// The codec stopped at a decode limit, so the message may be
			// valid. A limit met only while inspecting it does not override
			// the codec's failure: Figure A.3 checks the syntax first.
			pe.pAbortCause = PAbortCauseResourceLimitation
		case invalidTransactionEncoding(validation) || invalidTransactionEncoding(failure) || errors.Is(validation, ber.ErrExtraData):
			pe.pAbortCause = PAbortCauseBadlyFormattedTransactionPortion
		default:
			pe.pAbortCause = PAbortCauseIncorrectTransactionPortion
		}
	}()
	pe.MessageType = inspectedMessageType(t)
	if pe.MessageType == "" {
		pe.Err = ErrUnrecognizedMessageType
	}
	// Q.773 Table 8: a message is constructed; a primitive has no children.
	if !t.Constructed {
		return pe
	}
	if transactionOnly {
		return pe
	}
	// Without a source, the scan covers a whole TCMessage with the codec's
	// Q.773 clause 4.1.1 scope, so it stops where the codec does; parameters
	// stay TC-user syntax (ITU-T X.690 (02/2021) clause 8.15).
	validation = ber.ValidateBERElement(data, ber.TrackTCAPForm(opts)...)
	if errors.Is(validation, ber.ErrResourceLimit) {
		// Only the codec's limit skips repeat counting. An inspection limit
		// still permits counting immediate tags within the scan's budget.
		contents, _ := inspectedMessageContents(data, limits)
		children, _ := scanChildren(contents, limits)
		idCount = children.idCount
		pe.Err = joinErrors(pe.Err, validation)
		return pe
	}
	_, n, value, err := ber.DecodeTLV(data, opts...)
	if err != nil {
		value, n = inspectedMessageContents(data, limits)
	}
	// ITU-T Q.774 (06/97) Table 7: count immediate ID tags even when the
	// outer header is invalid or the last child cannot be delimited.
	children, scanErr := scanChildren(value, limits)
	idCount = children.idCount
	var rootFailure *ber.ElementError
	if validation != nil && errors.As(validation, &rootFailure) && len(rootFailure.ChildIndexes()) == 0 {
		pe.Err = joinErrors(pe.Err, firstLimit(validation))
		return pe
	}
	if n != 0 && n != len(data) {
		return pe
	}
	if err != nil {
		_, tagBytes, tagErr := ber.DecodeTag(data)
		if tagErr != nil {
			return pe
		}
		length, indefinite, lengthBytes, lengthErr := ber.DecodeLength(data[tagBytes:])
		if lengthErr != nil || !indefinite && length != len(data)-tagBytes-lengthBytes {
			return pe
		}
	}
	if err != nil || scanErr != nil {
		// A component portion that cannot be delimited is inspected from the
		// codec's location only where the scan stopped at it as well: a
		// malformed element after it breaks the transaction layout (Q.773
		// (06/97) clause 3.1).
		ok := false
		if scanErr == nil || scanStoppedAt(children, scanErr, validation) {
			children, ok = locatedComponentPrefix(value, validation, opts)
		}
		if !ok {
			pe.Err = joinErrors(pe.Err, firstLimit(err, scanErr))
			return pe
		}
		n = len(data)
	}
	// Q.773 clause 3.1 and Tables 3-7 establish the transaction portion
	// before Q.774 clause 3.2.2.2 permits inspection of the other portions.
	if pe.MessageType == "" || n != len(data) || !soundTransaction(children, pe.MessageType, prefix, opts) {
		return pe
	}
	dialogueFailure := isDialogueFailure(data, failure)
	var dialogue *Dialogue
	for _, child := range children.leading {
		t, _, value, delimErr := ber.DecodeTLV(child, opts...)
		if delimErr != nil {
			t, _ = ber.PeekTag(child)
			value = inspectedContents(child)
		}
		switch t.Number {
		case 11:
			var w wire.DialoguePortion
			err := w.UnmarshalBER(child, opts...)
			var d *Dialogue
			if err == nil {
				d, err = decodeDialogue(&w, pe.MessageType)
			}
			if errors.Is(err, ber.ErrResourceLimit) {
				pe.Err = err
				return pe
			}
			if err != nil {
				pe.Portion, pe.Err = PortionDialogue, err
				return pe
			}
			// A message rule can fail where the dialogue decodes on its
			// own (Q.773 (06/97) clause 4.2.3). An incorrect dialogue portion
			// aborts the dialogue (Q.774 (06/97) clause 3.2.2.1), so the
			// codec's location goes before any component failure.
			if dialogueFailure {
				pe.Portion = PortionDialogue
				return pe
			}
			if !ber.ToleranceEnabled(opts) {
				if err := messageDialogueFailure(data, children, opts); err != nil {
					pe.Portion, pe.Err = PortionDialogue, err
					return pe
				}
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
					// The first element of a component that cannot be
					// delimited may still be a complete invoke ID.
					ct, _ = ber.PeekTag(value)
					pe.Portion, pe.ComponentIndex, pe.ComponentType, pe.Err = PortionComponent, index, inspectedComponentType(ct), err
					if ct.Constructed {
						contents := inspectedContents(value)
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
						c, err = decodeComponent(w)
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
				var portion wire.ComponentPortion
				if err := portion.UnmarshalBER(child, opts...); err != nil {
					pe.Portion, pe.Err = PortionComponent, err
					return pe
				}
			}
		}
	}
	return pe
}

// The codec applies Q.773 (06/97) clause 4.2.3 to the message only after its
// BER checks, so an encoding fault in a component hides a dialogue portion
// the clause refuses. Ask the codec about the message without its component
// portion: an incorrect dialogue portion aborts the dialogue (Q.774 (06/97)
// clause 3.2.2.1), so its failure goes first. Only a failure the codec locates
// at the dialogue portion counts, and a limit met here changes nothing.
func messageDialogueFailure(data []byte, children messageChildren, opts []ber.DecodeOption) error {
	contents := inspectedContents(data)
	end := 0
	for _, child := range children.leading {
		if applicationChild(child, 12) {
			break
		}
		end += len(child)
	}
	t, _ := ber.PeekTag(data)
	probe, err := ber.EncodeTLV(t, contents[:end])
	if err != nil {
		return nil
	}
	var w wire.TCMessage
	err = w.UnmarshalBER(probe, opts...)
	if errors.Is(err, ber.ErrResourceLimit) || !isDialogueFailure(probe, err) {
		return nil
	}
	// Shortening the outer length may shorten its header. Keep both codec
	// locations relative to the original input, whose leading children match.
	if shift := len(data) - len(contents) - (len(probe) - end); shift != 0 {
		var decoded *wire.DecodeError
		var validation *ber.ValidationError
		if errors.As(err, &decoded) && errors.As(err, &validation) {
			offset := *validation.Offset + shift
			validation.Offset = &offset
			decoded.Cause = ber.LocateDecodeError(validation, ber.LocateDecodedElement(data, "TCAPMessages.TCMessage", opts))
		}
	}
	return err
}

// Q.773 (06/97) clause 4.1.1 governs encoding; its Annex A constraints
// instead describe validly encoded but incorrect transaction elements.
// ErrExtraData is excluded here: whole-element validation establishes
// trailing octets, and the codec reports leftover children of a constructed
// value as ErrUnexpectedElement.
func invalidTransactionEncoding(err error) bool {
	var validation *ber.ValidationError
	if errors.As(err, &validation) {
		return validation.Rule.Document == "ITU-T X.690" ||
			validation.Kind == ber.ProtocolRule && validation.Rule.Document == "ITU-T Q.773" && validation.Rule.Clause == "4.1.1"
	}
	return errors.Is(err, ber.ErrTruncated) || errors.Is(err, ber.ErrInvalidTag) ||
		errors.Is(err, ber.ErrInvalidLength) || errors.Is(err, ber.ErrIndefiniteLength) ||
		errors.Is(err, ber.ErrInvalidValue)
}

// isDialogueFailure uses the codec's wire location rather than its ASN.1
// path text. A single child index identifies a direct child of the message;
// Q.773 (06/97) clause 4.2.3 assigns APPLICATION 11 to the dialogue portion.
func isDialogueFailure(data []byte, failure error) bool {
	var validation *ber.ValidationError
	if !errors.As(failure, &validation) || len(validation.ChildIndexes) != 1 || validation.Offset == nil {
		return false
	}
	offset := *validation.Offset
	if offset < 0 || offset >= len(data) {
		return false
	}
	t, err := ber.PeekTag(data[offset:])
	return err == nil && t.Class == tag.ClassApplication && t.Constructed && t.Number == 11
}

// scanStoppedAt reports whether a scan that failed with scanErr stopped at
// the child of the message that holds the codec's failure. A malformed child
// is kept as the last one; at a decode limit, the child being read is not.
func scanStoppedAt(children messageChildren, scanErr, failure error) bool {
	var location *ber.ElementError
	if !errors.As(failure, &location) || len(location.ChildIndexes()) == 0 {
		return false
	}
	stopped := children.count - 1
	if errors.Is(scanErr, ber.ErrResourceLimit) {
		stopped = children.count
	}
	return location.ChildIndexes()[0] == stopped
}

// locatedComponentPrefix exposes only the leading children and the component
// portion identified by the codec's failure location. It never delimits a
// malformed container or accepts it as a complete BER element.
// ITU-T Q.774 (06/97) clause 3.2.2.2 and Table 5 require the first failing
// component even when a later component prevents delimiting its container.
func locatedComponentPrefix(contents []byte, failure error, opts []ber.DecodeOption) (messageChildren, bool) {
	var children messageChildren
	// Data that ends inside the message leaves its transaction portion
	// unestablished (ITU-T Q.774 (06/97) clause 3.3.4).
	var location *ber.ElementError
	if errors.Is(failure, ber.ErrTruncated) || !errors.As(failure, &location) || len(location.ChildIndexes()) < 2 {
		return children, false
	}
	index := location.ChildIndexes()[0]
	if index < 0 || index >= leadingChildren {
		return children, false
	}
	for i := 0; i <= index && len(contents) > 0; i++ {
		t, err := ber.PeekTag(contents)
		if err != nil {
			return children, false
		}
		if i == index {
			// X.690 (02/2021) clause 8.1.3.6 requires decoding the contents
			// to find an indefinite length. Q.774 clause 3.2.2.2 and Table 5
			// require inspecting earlier components when a later one is malformed.
			if t.Class != tag.ClassApplication || !t.Constructed || t.Number != 12 {
				return children, false
			}
			if _, _, _, err := ber.DecodeTLV(contents, opts...); err == nil {
				return children, false
			}
			_, tagBytes, err := ber.DecodeTag(contents)
			if err != nil {
				return children, false
			}
			_, indefinite, _, err := ber.DecodeLength(contents[tagBytes:])
			if err != nil || !indefinite {
				return children, false
			}
			children.add(contents)
			return children, true
		}
		_, n, _, err := ber.DecodeTLV(contents, opts...)
		if err != nil {
			return children, false
		}
		children.add(contents[:n])
		contents = contents[n:]
	}
	return children, false
}

// messageChildren is what inspection keeps of the immediate children of a
// message: the leading ones and their number, to establish the transaction
// layout before inspecting dialogue and components (Q.773 (06/97) clause 3.1),
// and immediate ID tag counts for derivability (Q.774 (06/97) Table 7).
type messageChildren struct {
	leading [][]byte
	count   int
	idCount [2]int
}

// A sound transaction portion has at most four elements (Q.773 (06/97) clause
// 3.1, Continue); inspection keeps one more to see that a message has more.
const leadingChildren = 5

func (c *messageChildren) add(child []byte) {
	if t, err := ber.PeekTag(child); err == nil && t.Class == tag.ClassApplication && (t.Number == 8 || t.Number == 9) {
		c.idCount[t.Number-8]++
	}
	if c.count < leadingChildren {
		c.leading = append(c.leading, child)
	}
	c.count++
}

// The scan reads immediate children within the decode limits to establish
// the transaction layout (ITU-T Q.773 (06/97) clause 3.1), keeping a malformed
// final child so that it cannot hide an invalid layout or a repeated ID tag
// (ITU-T Q.774 (06/97) Table 7).
func scanChildren(data []byte, limits ber.DecodeLimits) (messageChildren, error) {
	var children messageChildren
	budget := scanBudget{limits: limits, elements: 1}
	for len(data) > 0 {
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
			if depth++; 1+depth > b.limits.MaxDepth {
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

// inspectedMessageContents bounds an indefinite message at its matching EOC
// (X.690 (02/2021) clauses 8.1.3.6 and 8.1.5), using the child scan's budget.
// If delimiting fails, inspection keeps the remainder, as for a truncated
// message. The length is zero unless the matching EOC was found.
func inspectedMessageContents(data []byte, limits ber.DecodeLimits) ([]byte, int) {
	contents := inspectedContents(data)
	_, tn, err := ber.DecodeTag(data)
	if err != nil {
		return contents, 0
	}
	_, indefinite, ln, err := ber.DecodeLength(data[tn:])
	if err != nil || !indefinite {
		return contents, 0
	}
	budget := scanBudget{limits: limits, elements: 1}
	for pos := 0; pos < len(contents); {
		if len(contents)-pos >= 2 && contents[pos] == 0 && contents[pos+1] == 0 {
			if limits.MaxWork-budget.work < 2 {
				break
			}
			return contents[:pos], tn + ln + pos + 2
		}
		n, err := budget.elementLength(contents[pos:])
		if err != nil {
			break
		}
		pos += n
	}
	return contents, 0
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
// The codec's Prefix establishes acceptance of the required transaction IDs;
// inspection checks their positions without decoding or validating them again.
func soundTransaction(kept messageChildren, mt MessageType, prefix wire.TransactionPrefix, opts []ber.DecodeOption) bool {
	if kept.count > len(kept.leading) {
		return false
	}
	children := kept.leading
	var required []int
	switch mt {
	case MessageTypeBegin:
		if prefix.Otid == nil {
			return false
		}
		required = []int{8}
	case MessageTypeContinue:
		if prefix.Otid == nil || prefix.Dtid == nil {
			return false
		}
		required = []int{8, 9}
	case MessageTypeEnd, MessageTypeAbort:
		if prefix.Dtid == nil {
			return false
		}
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
		pos++
	}
	if mt == MessageTypeAbort {
		if pos == len(children) {
			return true
		}
		if pos+1 != len(children) {
			return false
		}
		if applicationChild(children[pos], 11) {
			return true
		}
		var reason wire.AbortReason
		return reason.UnmarshalBER(children[pos], opts...) == nil
	}
	if pos < len(children) && applicationChild(children[pos], 11) {
		pos++
	}
	if pos < len(children) && applicationChild(children[pos], 12) {
		pos++
	} else if mt == MessageTypeUnidirectional {
		return false
	}
	return pos == len(children)
}

func applicationChild(data []byte, number int) bool {
	t, err := ber.PeekTag(data)
	return err == nil && t.Class == tag.ClassApplication && t.Constructed && t.Number == number
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
// With tolerance, a value outside -128..127 that Parse accepts is
// derivable as well.
func derivableInvokeID(content []byte, opts []ber.DecodeOption) *int64 {
	_, n, _, err := ber.DecodeTLV(content, opts...)
	if err != nil {
		return nil
	}
	var id wire.TCInvokeIdSet
	if err := id.UnmarshalBER(content[:n], opts...); err != nil || id.Present == nil || !id.Present.IsInt64() {
		return nil
	}
	value := id.Present.Int64()
	return &value
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
