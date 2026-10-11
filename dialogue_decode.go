package tcap

import (
	"fmt"
	"slices"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// ITU-T Q.773 (06/97) clauses 3.2 and 4.2.3 identify known dialogue PDUs.
// An invalid known syntax never becomes opaque user data.
func decodeDialogue(dp *wire.DialoguePortion, mt MessageType, opts []ber.DecodeOption) (*Dialogue, error) {
	if dp == nil {
		return nil, nil
	}
	e := runtime.External(*dp)
	structured := slices.Equal(e.DirectReference, wire.DialogueAsId())
	uni := slices.Equal(e.DirectReference, wire.UniDialogueAsId())
	if !structured && !uni {
		x, err := decodeExternal(e)
		if err != nil {
			return nil, err
		}
		return &Dialogue{Opaque: &x}, nil
	}
	data, err := externalData(e)
	if err != nil {
		return nil, err
	}
	// Q.773 clause 3.2 defines only AARQ [0], AARE [1] and ABRT [4]
	// under dialogue-as-id, and only AUDT [0] under uniDialogue-as-id.
	t, err := ber.PeekTag(data)
	if err != nil {
		return nil, err
	}
	if t.Class != tag.ClassApplication || !t.Constructed || t.Number != 0 && (uni || t.Number != 1 && t.Number != 4) {
		return nil, ErrUnexpectedDialoguePDU
	}
	var d Dialogue
	if uni {
		var p wire.UniDialoguePDU
		if err := p.UnmarshalBER(data, opts...); err != nil {
			return nil, err
		}
		w := p.UnidialoguePDU
		acn, err := OIDFromArcs(w.ApplicationContextName...)
		if err != nil {
			return nil, err
		}
		v := &AUDT{ProtocolVersion: cloneBitsPointer(w.ProtocolVersion), ApplicationContextName: acn}
		if w.UserInformation != nil {
			ui, err := decodeExternals(w.UserInformation.Values)
			if err != nil {
				return nil, err
			}
			v.UserInformation = ui
		}
		d.Unidirectional = v
	} else {
		var p wire.DialoguePDU
		if err := p.UnmarshalBER(data, opts...); err != nil {
			return nil, err
		}
		switch {
		case p.DialogueRequest != nil:
			w := p.DialogueRequest
			acn, err := OIDFromArcs(w.ApplicationContextName...)
			if err != nil {
				return nil, err
			}
			v := &AARQ{ProtocolVersion: cloneBitsPointer(w.ProtocolVersion), ApplicationContextName: acn}
			if w.UserInformation != nil {
				ui, err := decodeExternals(w.UserInformation.Values)
				if err != nil {
					return nil, err
				}
				v.UserInformation = ui
			}
			d.Request = v
		case p.DialogueResponse != nil:
			w := p.DialogueResponse
			acn, err := OIDFromArcs(w.ApplicationContextName...)
			if err != nil {
				return nil, err
			}
			v := &AARE{ProtocolVersion: cloneBitsPointer(w.ProtocolVersion), ApplicationContextName: acn, Result: w.Result,
				ResultSourceDiagnostic: ResultSourceDiagnostic{DialogueServiceUser: clonePointer(w.ResultSourceDiagnostic.DialogueServiceUser), DialogueServiceProvider: clonePointer(w.ResultSourceDiagnostic.DialogueServiceProvider)}}
			if w.UserInformation != nil {
				ui, err := decodeExternals(w.UserInformation.Values)
				if err != nil {
					return nil, err
				}
				v.UserInformation = ui
			}
			d.Response = v
		case p.DialogueAbort != nil:
			w := p.DialogueAbort
			v := &ABRT{AbortSource: w.AbortSource}
			if w.UserInformation != nil {
				ui, err := decodeExternals(w.UserInformation.Values)
				if err != nil {
					return nil, err
				}
				v.UserInformation = ui
			}
			d.Abort = v
		default:
			return nil, ErrUnexpectedDialoguePDU
		}
	}
	// Q.774 Table 3 and clause 3.2.3; provider ABRT user information is accepted.
	if err := validateDialogue(&d, mt, false); err != nil {
		return nil, err
	}
	return &d, nil
}

// ITU-T X.690 (02/2021) clause 8.18 permits three data-value encodings.
// A known TCAP PDU carried as arbitrary bits must comprise whole octets.
func externalData(e runtime.External) ([]byte, error) {
	switch e.Encoding {
	case runtime.ExternalSingleASN1Type:
		return e.SingleASN1Type.Bytes, nil
	case runtime.ExternalOctetAligned:
		return e.OctetAligned, nil
	case runtime.ExternalArbitrary:
		if e.Arbitrary.BitLength >= 0 && e.Arbitrary.BitLength%8 == 0 && e.Arbitrary.BitLength/8 == len(e.Arbitrary.Bytes) {
			return e.Arbitrary.Bytes, nil
		}
	}
	return nil, fmt.Errorf("%w: known dialogue syntax requires whole octets", ErrExternalEncoding)
}

func decodeExternal(e runtime.External) (External, error) {
	v := External{IndirectReference: cloneBigInt(e.IndirectReference), DataValueDescriptor: clonePointer(e.DataValueDescriptor), Encoding: e.Encoding,
		SingleASN1Type: slices.Clone(e.SingleASN1Type.Bytes), OctetAligned: slices.Clone(e.OctetAligned), Arbitrary: cloneBits(e.Arbitrary)}
	if e.DirectReference != nil {
		oid, err := OIDFromArcs(e.DirectReference...)
		if err != nil {
			return v, err
		}
		v.DirectReference = oid
	}
	return v, nil
}

func decodeExternals(es []runtime.External) ([]External, error) {
	// The caller's non-nil collection pointer means present, even with nil Values.
	out := make([]External, len(es))
	for i, e := range es {
		v, err := decodeExternal(e)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
