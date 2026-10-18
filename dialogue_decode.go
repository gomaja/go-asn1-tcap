package tcap

import (
	"slices"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
)

// ITU-T Q.773 (06/97) clauses 3.2 and 4.2.3 identify known dialogue PDUs.
// An invalid known syntax never becomes opaque user data.
func decodeDialogue(dp *wire.DialoguePortion, mt MessageType) (*Dialogue, error) {
	if dp == nil {
		return nil, nil
	}
	var d Dialogue
	if p, ok := dp.UniDialogue(); ok {
		w := p.UnidialoguePDU
		acn, err := decodeOID(w.ApplicationContextName)
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
	} else if p, ok := dp.Dialogue(); ok {
		switch {
		case p.DialogueRequest != nil:
			w := p.DialogueRequest
			acn, err := decodeOID(w.ApplicationContextName)
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
			acn, err := decodeOID(w.ApplicationContextName)
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
	} else {
		e, err := dp.External()
		if err != nil {
			return nil, err
		}
		x, err := decodeExternal(e)
		if err != nil {
			return nil, err
		}
		d.Opaque = &x
	}
	// Q.774 Table 3 and clause 3.2.3; provider ABRT user information is accepted.
	if err := validateDialogue(&d, mt, false); err != nil {
		return nil, err
	}
	return &d, nil
}

func decodeExternal(e runtime.External) (External, error) {
	v := External{IndirectReference: cloneBigInt(e.IndirectReference), DataValueDescriptor: clonePointer(e.DataValueDescriptor), Encoding: e.Encoding,
		SingleASN1Type: slices.Clone(e.SingleASN1Type.Bytes), OctetAligned: slices.Clone(e.OctetAligned), Arbitrary: cloneBits(e.Arbitrary)}
	if !e.DirectReference.IsZero() {
		oid, err := decodeOID(e.DirectReference)
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
