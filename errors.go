package tcap

import (
	"errors"
	"fmt"
	"strings"
)

// Errors reported by Marshal and Parse. ASN.1 size and value constraints are
// reported as *ber.ConstraintError instead. BER structure errors retain the
// codec's causes, including parameter and EXTERNAL single-ASN1-type errors.
var (
	// ErrEmptyData reports that Parse received no octets.
	ErrEmptyData = errors.New("tcap: empty data")

	// ErrInvalidParseOption reports a nil ParseOption, WithConstraintTolerance(nil) or
	// decode limits that go-asn1 does not accept.
	ErrInvalidParseOption = errors.New("tcap: invalid parse option")

	// ErrNilMessage reports a Marshal call on a nil message.
	ErrNilMessage = errors.New("tcap: nil message")

	// ErrInvalidOID reports an object identifier that is not valid or not in
	// canonical dotted-decimal form.
	ErrInvalidOID = errors.New("tcap: invalid object identifier")

	// ErrUnrepresentableValue reports a valid value that does not fit its Go
	// type, such as a local code outside the int64 range.
	ErrUnrepresentableValue = errors.New("tcap: value cannot be represented")

	// ErrUnrecognizedMessageType reports a message tag that is not a TCAP
	// message type (ITU-T Q.773 (06/97) Table 8).
	ErrUnrecognizedMessageType = errors.New("tcap: unrecognized message type")

	// ErrUnrecognizedComponent reports a component tag that is not a TCAP
	// component type (Q.773 Table 19).
	ErrUnrecognizedComponent = errors.New("tcap: unrecognized component type")

	// ErrComponentNoAlternative and ErrComponentMultipleAlternatives report a
	// Component with no field or more than one field set.
	ErrComponentNoAlternative        = errors.New("tcap: component has no alternative")
	ErrComponentMultipleAlternatives = errors.New("tcap: component has multiple alternatives")

	// ErrCodeNoAlternative reports a missing operation or error code.
	ErrCodeNoAlternative = errors.New("tcap: code has no alternative")

	// ErrProblemNoAlternative and ErrProblemMultipleAlternatives report a
	// Problem with no field or more than one field set.
	ErrProblemNoAlternative        = errors.New("tcap: problem has no alternative")
	ErrProblemMultipleAlternatives = errors.New("tcap: problem has multiple alternatives")

	// ErrResultSourceDiagnosticNoAlternative and
	// ErrResultSourceDiagnosticMultipleAlternatives report a
	// ResultSourceDiagnostic with no field or more than one field set.
	ErrResultSourceDiagnosticNoAlternative        = errors.New("tcap: result-source-diagnostic has no alternative")
	ErrResultSourceDiagnosticMultipleAlternatives = errors.New("tcap: result-source-diagnostic has multiple alternatives")

	// ErrDialogueNoAlternative and ErrDialogueMultipleAlternatives report a
	// Dialogue with no field or more than one field set.
	ErrDialogueNoAlternative        = errors.New("tcap: dialogue has no alternative")
	ErrDialogueMultipleAlternatives = errors.New("tcap: dialogue has multiple alternatives")

	// ErrUnexpectedDialoguePDU reports a dialogue PDU that the message type
	// cannot carry (ITU-T Q.774 (06/97) Table 3), or a dialogue PDU that does
	// not belong to the abstract syntax named by the dialogue portion (Q.773
	// clause 4.2.3).
	ErrUnexpectedDialoguePDU = errors.New("tcap: unexpected dialogue PDU")

	// ErrUnexpectedDialogueResult reports an AARE whose result does not suit
	// the message: a Continue or an End carries an AARE that accepts the
	// dialogue, an Abort one that rejects it (Q.774 Table 3).
	ErrUnexpectedDialogueResult = errors.New("tcap: unexpected dialogue result")

	// ErrUnexpectedUserInformation reports user information in an ABRT whose
	// abort source is the dialogue service provider (Q.774 clause 3.2.2.1).
	ErrUnexpectedUserInformation = errors.New("tcap: unexpected user information")

	// ErrUnsupportedProtocolVersion reports a protocol-version that does not
	// offer version1 in an AARQ or an AUDT to be marshalled, or that is not
	// exactly version1 in an AARE (Q.774 clause 3.2.3).
	ErrUnsupportedProtocolVersion = errors.New("tcap: unsupported protocol version")

	// ErrAbortMultipleReasons reports an Abort with both PAbortCause and
	// Dialogue set.
	ErrAbortMultipleReasons = errors.New("tcap: abort has multiple reasons")

	// ErrMissingInvokeID reports a Return Result or a Return Error whose
	// invoke ID is NULL, or such an Invoke parsed with WithConstraintTolerance;
	// only a Reject may omit it (Q.773 Table 18). Without tolerance, the codec
	// reports a NULL Invoke ID as a *ber.ConstraintError.
	ErrMissingInvokeID = errors.New("tcap: missing invoke ID")

	// ErrInvalidLinkedID reports a linked ID that is not encoded as
	// [0] IMPLICIT INTEGER (Q.773 Table 20), such as the X.880 alternative
	// absent [1] NULL.
	ErrInvalidLinkedID = errors.New("tcap: invalid linked ID")

	// ErrExternalEncoding reports an External whose Encoding is not one of
	// the three EXTERNAL encodings, or whose other encoding fields are not
	// empty.
	ErrExternalEncoding = errors.New("tcap: invalid EXTERNAL encoding")
)

// Portion names the portion of a TCAP message in which Parse failed.
type Portion string

// Message portions (ITU-T Q.773 (06/97) clause 4).
const (
	PortionTransaction Portion = "transaction"
	PortionDialogue    Portion = "dialogue"
	PortionComponent   Portion = "component"
)

// ComponentType names a component type of ITU-T Q.773 (06/97) Table 19. It
// identifies the failing component in a *ParseError.
type ComponentType string

// Component types, Q.773 Table 19.
const (
	ComponentTypeInvoke              ComponentType = "Invoke"
	ComponentTypeReturnResultLast    ComponentType = "ReturnResultLast"
	ComponentTypeReturnResultNotLast ComponentType = "ReturnResultNotLast"
	ComponentTypeReturnError         ComponentType = "ReturnError"
	ComponentTypeReject              ComponentType = "Reject"
)

// ParseError reports why Parse failed, with what a TCAP stack needs to apply
// the abnormal procedures of ITU-T Q.774 (06/97): a P-Abort for a failure in
// the transaction portion (clause 3.3.4, Table 7), an ABRT from the dialogue
// service provider for one in the dialogue portion (clause 3.2.2.1), and a
// Reject for one in the component portion (clause 3.2.2.2, Table 5), except
// a malformed Reject, which is discarded and reported only to the local user.
//
// None of its fields alias the parsed data.
type ParseError struct {
	// MessageType is the type of the message, or "" when the message type is
	// not recognized or its tag cannot be decoded.
	MessageType MessageType

	// OTID and DTID are the transaction IDs that could be derived from where
	// the message type carries them: complete, well-formed, not repeated, and
	// 1 to 4 octets long (any length with WithConstraintTolerance, empty
	// included). They are nil otherwise. Repetitions are looked for up to an
	// element that cannot be decoded. When the message exceeds the decode
	// limits, an ID is taken from where the message type carries it, without
	// looking for repetitions, only if it and the elements before it are
	// valid and within the limits as go-asn1 counts them. An input longer
	// than MaxWork, a limit that go-asn1 reports without a location, or a
	// message whose type is not recognized then has no IDs. A message that decoded completely
	// keeps its IDs when the dialogue PDU inside its EXTERNAL exceeds the
	// limits.
	OTID TransactionID
	DTID TransactionID

	// Portion is the portion of the message that failed.
	Portion Portion

	// ComponentIndex is the position of the failing component within the
	// component portion, or -1.
	ComponentIndex int

	// ComponentType is the type of the failing component, or "" when its tag
	// is not a component type or ComponentIndex is -1. A malformed Reject
	// is discarded and reported locally; it is never answered with a Reject
	// (ITU-T Q.774 (06/97) clause 3.2.2.2 and Table 5).
	ComponentType ComponentType

	// InvokeID is the invoke ID of the failing component, when it can be
	// derived: its first element is an INTEGER from -128 to 127 (any value
	// with WithConstraintTolerance).
	InvokeID *int64

	// Dialogue and Components are set when ComponentIndex is nonnegative:
	// the decoded dialogue portion, and the valid components that precede
	// the failing one. Components that follow it are discarded (Q.774 clause
	// 3.2.2.2).
	Dialogue   *Dialogue
	Components []Component

	// Err is the cause. When Portion is the dialogue or component portion,
	// it is the failure of that dialogue portion or of the component that
	// ComponentIndex designates, not of anything that follows. When it is
	// the transaction portion, it is what ended the decoding of the message,
	// which can lie in any portion, after ErrUnrecognizedMessageType and a
	// decode limit met only while inspecting the message, if any.
	Err error
}

// Error describes the failure.
func (e *ParseError) Error() string {
	name := string(e.MessageType)
	if name == "" {
		name = "message"
	}
	component := ""
	if e.ComponentIndex >= 0 {
		component = fmt.Sprintf(" component %d", e.ComponentIndex)
	}
	return fmt.Sprintf("tcap: parse %s: %s portion%s: %s", name, e.Portion, component, causeText(e.Err))
}

// Unwrap returns the cause.
func (e *ParseError) Unwrap() error {
	return e.Err
}

// FieldError reports the field of a message that Marshal rejected, by its
// path from the message, such as "Components[1].Invoke.Parameter".
type FieldError struct {
	Path string
	Err  error
}

// Error describes the failure.
func (e *FieldError) Error() string {
	return fmt.Sprintf("tcap: %s: %s", e.Path, causeText(e.Err))
}

// causeText returns the message of a wrapped error without the package
// prefix that the enclosing message already carries.
func causeText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return strings.TrimPrefix(err.Error(), "tcap: ")
}

// Unwrap returns the cause.
func (e *FieldError) Unwrap() error {
	return e.Err
}

type joinedError struct{ causes []error }

func (e *joinedError) Error() string {
	messages := make([]string, len(e.causes))
	for i, err := range e.causes {
		messages[i] = err.Error()
	}
	return strings.Join(messages, "; ")
}

func (e *joinedError) Unwrap() []error { return e.causes }

func joinErrors(errs ...error) error {
	var causes []error
	for _, err := range errs {
		if err != nil {
			causes = append(causes, err)
		}
	}
	if len(causes) == 0 {
		return nil
	}
	if len(causes) == 1 {
		return causes[0]
	}
	return &joinedError{causes: causes}
}
