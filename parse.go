package tcap

import (
	asn1tcap "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// Parse decodes BER-encoded TCAP bytes into a TCAP message.
// It handles both DER and indefinite-length BER natively.
func Parse(data []byte) (TCAP, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	var msg asn1tcap.TCMessage
	if err := msg.UnmarshalBER(data); err != nil {
		return nil, newParseError("Parse", "UnmarshalBER", err)
	}

	result, err := convertTCMessageToTCAP(&msg)
	if err != nil {
		return nil, newParseError("Parse", "convert", err)
	}

	return result, nil
}
