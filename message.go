package tcap

import (
	"encoding/hex"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// Message is a TCAP message: *Begin, *Continue, *End, *Abort or
// *Unidirectional (ITU-T Q.773 (06/97) clause 3.1, TCMessage).
type Message interface {
	// Marshal validates the message and returns its BER encoding. The
	// result never aliases the message.
	Marshal() ([]byte, error)

	isMessage()
}

// MessageType names a TCAP message type. It identifies the message in a
// *ParseError, including when the message itself could not be decoded.
type MessageType string

// Message types, ITU-T Q.773 (06/97) Table 8.
const (
	MessageTypeUnidirectional MessageType = "Unidirectional"
	MessageTypeBegin          MessageType = "Begin"
	MessageTypeEnd            MessageType = "End"
	MessageTypeContinue       MessageType = "Continue"
	MessageTypeAbort          MessageType = "Abort"
)

// TransactionID is an originating or destination transaction ID: an opaque
// value of 1 to 4 octets (ITU-T Q.773 (06/97) clause 4.2.1.3).
type TransactionID []byte

// String returns the transaction ID in lowercase hexadecimal.
func (id TransactionID) String() string {
	return hex.EncodeToString(id)
}

// Begin starts a transaction (Q.773 Table 4).
//
// A nil Dialogue omits the dialogue portion. A nil Components omits the
// component portion; a present component portion holds at least one
// component, so a non-nil empty slice does not marshal.
type Begin struct {
	OTID       TransactionID
	Dialogue   *Dialogue
	Components []Component
}

// Marshal validates and encodes the Begin message.
func (m *Begin) Marshal() ([]byte, error) {
	return marshalMessage(m)
}

func (*Begin) isMessage() {}

// Continue continues a transaction (Q.773 Table 6). OTID identifies the
// transaction at the sender and DTID at the receiver.
type Continue struct {
	OTID       TransactionID
	DTID       TransactionID
	Dialogue   *Dialogue
	Components []Component
}

// Marshal validates and encodes the Continue message.
func (m *Continue) Marshal() ([]byte, error) {
	return marshalMessage(m)
}

func (*Continue) isMessage() {}

// End ends a transaction (Q.773 Table 5).
type End struct {
	DTID       TransactionID
	Dialogue   *Dialogue
	Components []Component
}

// Marshal validates and encodes the End message.
func (m *End) Marshal() ([]byte, error) {
	return marshalMessage(m)
}

func (*End) isMessage() {}

// Abort ends a transaction abnormally (Q.773 Table 7).
//
// The abort reason is optional: PAbortCause is set when the transaction
// sub-layer aborts, Dialogue (the u-abortCause) when the TC-user or the
// dialogue service provider aborts. At most one of them is set.
type Abort struct {
	DTID        TransactionID
	PAbortCause *PAbortCause
	Dialogue    *Dialogue
}

// Marshal validates and encodes the Abort message.
func (m *Abort) Marshal() ([]byte, error) {
	return marshalMessage(m)
}

func (*Abort) isMessage() {}

// PAbortCause is the P-Abort cause of an Abort sent by the transaction
// sub-layer (ITU-T Q.773 (06/97) Annex A, TCAPMessages, P-AbortCause). Build
// one with NewPAbortCause and compare one with AsInt64 against these
// constants.
type PAbortCause = wire.PAbortCause

// The named numbers of PAbortCause.
const (
	PAbortCauseUnrecognizedMessageType          = wire.PAbortCauseUnrecognizedMessageType
	PAbortCauseUnrecognizedTransactionID        = wire.PAbortCauseUnrecognizedTransactionID
	PAbortCauseBadlyFormattedTransactionPortion = wire.PAbortCauseBadlyFormattedTransactionPortion
	PAbortCauseIncorrectTransactionPortion      = wire.PAbortCauseIncorrectTransactionPortion
	PAbortCauseResourceLimitation               = wire.PAbortCauseResourceLimitation
)

// NewPAbortCause returns the PAbortCause with the given value.
func NewPAbortCause(value int64) PAbortCause {
	return wire.NewPAbortCauseInt64(value)
}

// Unidirectional carries components outside a transaction (Q.773 Table 3).
// Its component portion is mandatory: Components holds at least one
// component.
type Unidirectional struct {
	Dialogue   *Dialogue
	Components []Component
}

// Marshal validates and encodes the Unidirectional message.
func (m *Unidirectional) Marshal() ([]byte, error) {
	return marshalMessage(m)
}

func (*Unidirectional) isMessage() {}
