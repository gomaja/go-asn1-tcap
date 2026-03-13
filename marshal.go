package tcap

func marshalTCMessage(msg interface{ MarshalBER() ([]byte, error) }) ([]byte, error) {
	data, err := msg.MarshalBER()
	if err != nil {
		return nil, newParseError("Marshal", "MarshalBER", err)
	}
	return data, nil
}
