package tcap

import (
	"errors"
	"fmt"

	asn1tcap "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// MessageType identifies the type of TCAP message.
type MessageType string

const (
	MessageTypeUnidirectional MessageType = "Unidirectional"
	MessageTypeBegin          MessageType = "Begin"
	MessageTypeEnd            MessageType = "End"
	MessageTypeContinue       MessageType = "Continue"
	MessageTypeAbort          MessageType = "Abort"
)

// TCAP represents a CHOICE of TCAP message types.
type TCAP interface {
	Marshal() ([]byte, error)
	MessageType() MessageType
}

// TransactionID is 1 to 4 bytes in BigEndian format per ITU-T Q.773.
type TransactionID []byte

// UnidirectionalTCAP represents a one-way TCAP message.
type UnidirectionalTCAP struct {
	Dialogue        *Dialogue
	Components      []Component
	componentsIndef bool // true if original used indefinite-length encoding
}

// BeginTCAP represents a TCAP transaction initiation message.
type BeginTCAP struct {
	Otid            TransactionID
	Dialogue        *Dialogue
	Components      []Component
	componentsIndef bool // true if original used indefinite-length encoding
}

// EndTCAP represents a TCAP transaction termination message.
type EndTCAP struct {
	Dtid            TransactionID
	Dialogue        *Dialogue
	Components      []Component
	componentsIndef bool // true if original used indefinite-length encoding
}

// ContinueTCAP represents a TCAP transaction continuation message.
type ContinueTCAP struct {
	Otid            TransactionID
	Dtid            TransactionID
	Dialogue        *Dialogue
	Components      []Component
	componentsIndef bool // true if original used indefinite-length encoding
}

// AbortTCAP represents a TCAP transaction abort message.
type AbortTCAP struct {
	Dtid        TransactionID
	PAbortCause *asn1tcap.PAbortCause
	UAbortCause []byte // raw dialogue portion bytes for user abort
}

// Component represents a CHOICE of TCAP component types.
// Exactly one field should be non-nil.
type Component struct {
	Invoke              *Invoke
	ReturnResultLast    *ReturnResult
	ReturnResultNotLast *ReturnResult
	ReturnError         *ReturnError
	Reject              *Reject
}

// Invoke represents a TCAP invoke component.
type Invoke struct {
	InvokeID  int    // range -128 to 127
	LinkedID  *int   // optional linked invoke ID
	OpCode    int64  // local operation code
	Parameter []byte // raw BER-encoded parameter
}

// ReturnResult represents a TCAP return result component.
type ReturnResult struct {
	InvokeID  int    // range -128 to 127
	OpCode    *int64 // optional operation code
	Parameter []byte // raw BER-encoded parameter
}

// ReturnError represents a TCAP return error component.
type ReturnError struct {
	InvokeID  int    // range -128 to 127
	ErrorCode int64
	Parameter []byte // raw BER-encoded parameter
}

// Reject represents a TCAP reject component.
type Reject struct {
	InvokeID            *int                        // nil means not derivable
	GeneralProblem      *asn1tcap.GeneralProblem
	InvokeProblem       *asn1tcap.InvokeProblem
	ReturnResultProblem *asn1tcap.ReturnResultProblem
	ReturnErrorProblem  *asn1tcap.ReturnErrorProblem
}

// Dialogue holds the dialogue portion of a TCAP message.
type Dialogue struct {
	DialogAsId []uint64 // OID for dialogue AS

	Request  *DialogueRequest
	Response *DialogueResponse
	Abort    *DialogueAbort
}

// DialogueRequest represents an AARQ APDU (association request).
type DialogueRequest struct {
	ProtocolVersion        *uint8
	ApplicationContextName []uint64 // OID
	UserInformation        []byte
}

// DialogueResponse represents an AARE APDU (association response).
type DialogueResponse struct {
	ProtocolVersion        *uint8
	ApplicationContextName []uint64 // OID
	Result                 asn1tcap.AssociateResult
	ResultSourceDiagnostic ResultSourceDiagnostic
	UserInformation        []byte
}

// ResultSourceDiagnostic is a CHOICE — exactly one field should be non-nil.
type ResultSourceDiagnostic struct {
	DialogueServiceUser     *int64
	DialogueServiceProvider *int64
}

// DialogueAbort represents an ABRT APDU.
type DialogueAbort struct {
	AbortSource     asn1tcap.ABRTSource
	UserInformation []byte
}

// NewDialogueResponseFromDialogueRequest creates a dialogue response
// mirroring the request's protocol version and ACN.
func NewDialogueResponseFromDialogueRequest(dialogueRQ *Dialogue) (*Dialogue, error) {
	if dialogueRQ == nil {
		return nil, nil
	}
	if dialogueRQ.Request == nil {
		return nil, errors.New("dialogue request is nil")
	}

	return &Dialogue{
		DialogAsId: dialogueRQ.DialogAsId,
		Response: &DialogueResponse{
			ProtocolVersion:        dialogueRQ.Request.ProtocolVersion,
			ApplicationContextName: dialogueRQ.Request.ApplicationContextName,
		},
	}, nil
}

// validateTransactionID validates that a transaction ID meets ITU-T Q.773 requirements.
func validateTransactionID(tid []byte, fieldName string) error {
	if len(tid) < MinTransactionIDLength || len(tid) > MaxTransactionIDLength {
		return newValidationError(fieldName, len(tid),
			fmt.Errorf("must be %d to %d bytes in length, got %d bytes",
				MinTransactionIDLength, MaxTransactionIDLength, len(tid)))
	}
	return nil
}

// validateInvokeID validates that an invoke ID is within the valid range.
func validateInvokeID(invID int, fieldName string) error {
	if invID < MinInvokeID || invID > MaxInvokeID {
		return newValidationError(fieldName, invID,
			fmt.Errorf("must be in range %d to %d, got %d",
				MinInvokeID, MaxInvokeID, invID))
	}
	return nil
}

func newDialogueRequest(acn, acnVersion int) *Dialogue {
	return &Dialogue{
		DialogAsId: DefaultDialogueAsId,
		Request: &DialogueRequest{
			ProtocolVersion:        uint8Ptr(DefaultProtocolVersion),
			ApplicationContextName: buildACN(acn, acnVersion),
		},
	}
}

func newDialogueResponse(acn, acnVersion int) *Dialogue {
	return &Dialogue{
		DialogAsId: DefaultDialogueAsId,
		Response: &DialogueResponse{
			ProtocolVersion:        uint8Ptr(DefaultProtocolVersion),
			ApplicationContextName: buildACN(acn, acnVersion),
		},
	}
}

func buildACN(acn, acnVersion int) []uint64 {
	result := make([]uint64, len(DefaultAcnPrefix)+2)
	copy(result, DefaultAcnPrefix)
	result[len(DefaultAcnPrefix)] = uint64(acn)
	result[len(DefaultAcnPrefix)+1] = uint64(acnVersion)
	return result
}
