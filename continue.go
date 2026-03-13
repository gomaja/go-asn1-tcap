package tcap

// ContinueOption represents a functional option for configuring Continue TCAP messages.
type ContinueOption func(*ContinueTCAP) error

// NewContinue creates a Continue TCAP message using the options pattern.
func NewContinue(otid, dtid []byte, options ...ContinueOption) (TCAP, error) {
	if err := validateTransactionID(otid, "otid"); err != nil {
		return nil, err
	}
	if err := validateTransactionID(dtid, "dtid"); err != nil {
		return nil, err
	}

	tcContinue := &ContinueTCAP{
		Otid: otid,
		Dtid: dtid,
	}

	for _, opt := range options {
		if err := opt(tcContinue); err != nil {
			return nil, err
		}
	}

	return tcContinue, nil
}

// WithContinueDialogueRequest adds a dialogue request to a Continue TCAP message.
func WithContinueDialogueRequest(acn, acnVersion int) ContinueOption {
	return func(cont *ContinueTCAP) error {
		cont.Dialogue = newDialogueRequest(acn, acnVersion)
		return nil
	}
}

// WithContinueDialogueResponse adds a dialogue response to a Continue TCAP message.
func WithContinueDialogueResponse(acn, acnVersion int) ContinueOption {
	return func(cont *ContinueTCAP) error {
		cont.Dialogue = newDialogueResponse(acn, acnVersion)
		return nil
	}
}

// WithContinueDialogueObject adds a dialogue object to a Continue TCAP message.
func WithContinueDialogueObject(dialogue *Dialogue) ContinueOption {
	return func(cont *ContinueTCAP) error {
		cont.Dialogue = dialogue
		return nil
	}
}

// WithContinueInvoke adds an Invoke component to a Continue TCAP message.
func WithContinueInvoke(invID int, opCode int64, payload []byte) ContinueOption {
	return func(cont *ContinueTCAP) error {
		if err := validateInvokeID(invID, "invID"); err != nil {
			return err
		}
		cont.Components = append(cont.Components, Component{
			Invoke: &Invoke{
				InvokeID:  invID,
				OpCode:    opCode,
				Parameter: payload,
			},
		})
		return nil
	}
}

// WithContinueReturnResultLast adds a ReturnResultLast component to a Continue TCAP message.
func WithContinueReturnResultLast(invID int, opCode *int64, payload []byte) ContinueOption {
	return func(cont *ContinueTCAP) error {
		if err := validateInvokeID(invID, "invID"); err != nil {
			return err
		}
		cont.Components = append(cont.Components, Component{
			ReturnResultLast: &ReturnResult{
				InvokeID:  invID,
				OpCode:    opCode,
				Parameter: payload,
			},
		})
		return nil
	}
}

// Marshal encodes the ContinueTCAP message to BER bytes.
func (tcContinue *ContinueTCAP) Marshal() ([]byte, error) {
	msg, err := convertContinueTCAPToASN1(tcContinue)
	if err != nil {
		return nil, err
	}
	return marshalTCMessage(&msg)
}

// MessageType returns the message type identifier.
func (tcContinue *ContinueTCAP) MessageType() MessageType {
	return MessageTypeContinue
}
