package tcap

// EndOption represents a functional option for configuring End TCAP messages.
type EndOption func(*EndTCAP) error

// NewEnd creates an End TCAP message using the options pattern.
func NewEnd(dtid []byte, options ...EndOption) (TCAP, error) {
	if err := validateTransactionID(dtid, "dtid"); err != nil {
		return nil, err
	}

	tcEnd := &EndTCAP{
		Dtid: dtid,
	}

	for _, opt := range options {
		if err := opt(tcEnd); err != nil {
			return nil, err
		}
	}

	return tcEnd, nil
}

// WithEndDialogueResponse adds a dialogue response to an End TCAP message.
func WithEndDialogueResponse(acn, acnVersion int) EndOption {
	return func(end *EndTCAP) error {
		end.Dialogue = newDialogueResponse(acn, acnVersion)
		return nil
	}
}

// WithEndDialogueObject adds a dialogue object to an End TCAP message.
func WithEndDialogueObject(dialogue *Dialogue) EndOption {
	return func(end *EndTCAP) error {
		end.Dialogue = dialogue
		return nil
	}
}

// WithEndReturnResultLast adds a ReturnResultLast component to an End TCAP message.
func WithEndReturnResultLast(invID int, opCode *int64, payload []byte) EndOption {
	return func(end *EndTCAP) error {
		if err := validateInvokeID(invID, "invID"); err != nil {
			return err
		}
		end.Components = append(end.Components, Component{
			ReturnResultLast: &ReturnResult{
				InvokeID:  invID,
				OpCode:    opCode,
				Parameter: payload,
			},
		})
		return nil
	}
}

// WithEndReturnError adds a ReturnError component to an End TCAP message.
func WithEndReturnError(invID int, errorCode int64, parameter []byte) EndOption {
	return func(end *EndTCAP) error {
		if err := validateInvokeID(invID, "invID"); err != nil {
			return err
		}
		end.Components = append(end.Components, Component{
			ReturnError: &ReturnError{
				InvokeID:  invID,
				ErrorCode: errorCode,
				Parameter: parameter,
			},
		})
		return nil
	}
}

// Marshal encodes the EndTCAP message to BER bytes.
func (tcEnd *EndTCAP) Marshal() ([]byte, error) {
	msg, err := convertEndTCAPToASN1(tcEnd)
	if err != nil {
		return nil, err
	}
	return marshalTCMessage(&msg)
}

// MessageType returns the message type identifier.
func (tcEnd *EndTCAP) MessageType() MessageType {
	return MessageTypeEnd
}
