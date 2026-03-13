package tcap

// BeginOption represents a functional option for configuring Begin TCAP messages.
type BeginOption func(*BeginTCAP) error

// NewBegin creates a Begin TCAP message using the options pattern.
// Parameters:
//   - otid: Originating Transaction ID, size from 1 to 4 bytes in BigEndian format.
func NewBegin(otid []byte, options ...BeginOption) (TCAP, error) {
	if err := validateTransactionID(otid, "otid"); err != nil {
		return nil, err
	}

	tcBegin := &BeginTCAP{
		Otid: otid,
	}

	for _, opt := range options {
		if err := opt(tcBegin); err != nil {
			return nil, err
		}
	}

	return tcBegin, nil
}

// WithBeginDialogueRequest adds a dialogue request to a Begin TCAP message.
func WithBeginDialogueRequest(acn, acnVersion int) BeginOption {
	return func(begin *BeginTCAP) error {
		begin.Dialogue = newDialogueRequest(acn, acnVersion)
		return nil
	}
}

// WithBeginDialogueObject adds a dialogue object to a Begin TCAP message.
func WithBeginDialogueObject(dialogue *Dialogue) BeginOption {
	return func(begin *BeginTCAP) error {
		begin.Dialogue = dialogue
		return nil
	}
}

// WithBeginInvoke adds an Invoke component to a Begin TCAP message.
func WithBeginInvoke(invID int, opCode int64, payload []byte) BeginOption {
	return func(begin *BeginTCAP) error {
		if err := validateInvokeID(invID, "invID"); err != nil {
			return err
		}
		begin.Components = append(begin.Components, Component{
			Invoke: &Invoke{
				InvokeID:  invID,
				OpCode:    opCode,
				Parameter: payload,
			},
		})
		return nil
	}
}

// Marshal encodes the BeginTCAP message to BER bytes.
func (tcBegin *BeginTCAP) Marshal() ([]byte, error) {
	msg, err := convertBeginTCAPToASN1(tcBegin)
	if err != nil {
		return nil, err
	}
	return marshalTCMessage(&msg)
}

// MessageType returns the message type identifier.
func (tcBegin *BeginTCAP) MessageType() MessageType {
	return MessageTypeBegin
}
