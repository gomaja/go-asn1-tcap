package tcap

import "fmt"

func marshalTCMessage(msg interface{ MarshalBER() ([]byte, error) }) ([]byte, error) {
	data, err := msg.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("marshal BER: %w", err)
	}
	return data, nil
}
