package tcap

// Marshal encodes the UnidirectionalTCAP message to BER bytes.
func (tcUnidirectional *UnidirectionalTCAP) Marshal() ([]byte, error) {
	msg, err := convertUnidirectionalTCAPToASN1(tcUnidirectional)
	if err != nil {
		return nil, err
	}
	return marshalTCMessage(&msg)
}

// MessageType returns the message type identifier.
func (tcUnidirectional *UnidirectionalTCAP) MessageType() MessageType {
	return MessageTypeUnidirectional
}
