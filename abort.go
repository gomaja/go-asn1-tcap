package tcap

// Marshal encodes the AbortTCAP message to BER bytes.
func (tcAbort *AbortTCAP) Marshal() ([]byte, error) {
	msg, err := convertAbortTCAPToASN1(tcAbort)
	if err != nil {
		return nil, err
	}
	return marshalTCMessage(&msg)
}

// MessageType returns the message type identifier.
func (tcAbort *AbortTCAP) MessageType() MessageType {
	return MessageTypeAbort
}
