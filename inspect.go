package tcap

import (
	"errors"
	"fmt"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// ITU-T Q.774 (06/97) Tables 5 and 7: inspection derives abnormal-procedure
// context after a failure. It never accepts a message or publishes reports.
func inspectFailure(data []byte, opts []ber.DecodeOption) *ParseError {
	opts, _ = ber.StageDecodeReports(opts)
	pe := &ParseError{Portion: PortionTransaction, ComponentIndex: -1}
	t, err := ber.PeekTag(data)
	if err != nil {
		return pe
	}
	pe.MessageType = inspectedMessageType(t)
	if pe.MessageType == "" {
		pe.Err = ErrUnrecognizedMessageType
	}
	_, _, children, err := ber.DecodeTLV(data, opts...)
	if err != nil {
		return pe
	}
	// Derive both IDs before locating a failed portion, including UNKNOWN messages.
	for rest := children; len(rest) > 0; {
		t, n, value, err := ber.DecodeTLV(rest, opts...)
		if err != nil {
			break
		}
		if t.Class == tag.ClassApplication && !t.Constructed {
			if t.Number == 8 {
				pe.OTID = derivableTID(value)
			}
			if t.Number == 9 {
				pe.DTID = derivableTID(value)
			}
		}
		rest = rest[n:]
	}
	var dialogue *Dialogue
	for len(children) > 0 {
		t, n, value, err := ber.DecodeTLV(children, opts...)
		if err != nil {
			return pe
		}
		data := children[:n]
		children = children[n:]
		if t.Class != tag.ClassApplication {
			continue
		}
		switch t.Number {
		case 11:
			var w wire.DialoguePortion
			err := w.UnmarshalBER(data, opts...)
			if err == nil {
				dialogue, err = decodeDialogue(&w, pe.MessageType, opts)
			}
			if err != nil {
				pe.Portion = PortionDialogue
				return pe
			}
		case 12:
			var prefix []Component
			index := 0
			for len(value) > 0 {
				ct, n, content, err := ber.DecodeTLV(value, opts...)
				if err != nil {
					pe.Portion, pe.ComponentIndex, pe.Dialogue, pe.Components = PortionComponent, index, dialogue, prefix
					return pe
				}
				var c Component
				if !recognizedComponent(ct) {
					err = ErrUnrecognizedComponent
					pe.Err = errors.Join(pe.Err, err)
				} else {
					var w wire.Component
					err = w.UnmarshalBER(value[:n], opts...)
					if err == nil {
						c, err = decodeComponent(w, fmt.Sprintf("Components[%d]", index), opts)
					}
				}
				if err != nil {
					pe.Portion, pe.ComponentIndex, pe.InvokeID, pe.Dialogue, pe.Components = PortionComponent, index, derivableInvokeID(content, opts), dialogue, prefix
					return pe
				}
				prefix = append(prefix, c)
				value = value[n:]
				index++
			}
			// The generated parent enforces ComponentPortion SIZE (1..MAX).
			if _, err := wire.UnmarshalBERComponentPortion(data, opts...); err != nil {
				pe.Portion, pe.Dialogue, pe.Components = PortionComponent, dialogue, prefix
				return pe
			}
		case 10:
			var reason wire.AbortReason
			if err := reason.UnmarshalBER(data, opts...); err != nil {
				return pe
			}
		}
	}
	return pe
}

// ITU-T Q.773 (06/97) Table 8 requires constructed APPLICATION message tags.
func inspectedMessageType(t tag.Tag) MessageType {
	if t.Class != tag.ClassApplication || !t.Constructed {
		return ""
	}
	switch t.Number {
	case 1:
		return MessageTypeUnidirectional
	case 2:
		return MessageTypeBegin
	case 4:
		return MessageTypeEnd
	case 5:
		return MessageTypeContinue
	case 7:
		return MessageTypeAbort
	}
	return ""
}

// Q.773 Table 19 assigns constructed context-specific component tags.
func recognizedComponent(t tag.Tag) bool {
	return t.Class == tag.ClassContextSpecific && t.Constructed && (t.Number >= 1 && t.Number <= 4 || t.Number == 7)
}

// Q.773 clause 4.2.2.2 and Q.774 Table 5: derive only a valid first INTEGER.
func derivableInvokeID(content []byte, opts []ber.DecodeOption) *int64 {
	t, _, value, err := ber.DecodeTLV(content, opts...)
	if err != nil || t.Class != tag.ClassUniversal || t.Number != tag.TagInteger || t.Constructed {
		return nil
	}
	n, err := ber.DecodeIntegerValue(value)
	if err != nil || n < -128 || n > 127 {
		return nil
	}
	return &n
}

func inspectComponentID(data []byte, index int, opts []ber.DecodeOption) *int64 {
	if index < 0 {
		return nil
	}
	_, _, rest, err := ber.DecodeTLV(data, opts...)
	if err != nil {
		return nil
	}
	for len(rest) > 0 {
		t, n, value, err := ber.DecodeTLV(rest, opts...)
		if err != nil {
			return nil
		}
		if t.Class == tag.ClassApplication && t.Number == 12 {
			for i := 0; len(value) > 0; i++ {
				_, n, content, err := ber.DecodeTLV(value, opts...)
				if err != nil {
					return nil
				}
				if i == index {
					return derivableInvokeID(content, opts)
				}
				value = value[n:]
			}
			return nil
		}
		rest = rest[n:]
	}
	return nil
}
