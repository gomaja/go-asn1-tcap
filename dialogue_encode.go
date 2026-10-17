package tcap

import (
	"fmt"
	"slices"

	"github.com/gomaja/go-asn1/runtime"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// ITU-T Q.773 (06/97) Tables 30-37 identify the dialogue abstract syntax.
func encodeDialogue(d *Dialogue) (*wire.DialoguePortion, error) {
	if d == nil {
		return nil, nil
	}
	if d.Opaque != nil {
		// Q.773 clause 4.2.3 and Q.774 Table 3 require the sender rules
		// of the structured alternatives for these abstract syntaxes.
		if d.Opaque.DirectReference != "" {
			arcs, err := encodeOID(d.Opaque.DirectReference, "Dialogue.Opaque.DirectReference")
			if err != nil {
				return nil, err
			}
			if arcs == wire.DialogueAsId() || arcs == wire.UniDialogueAsId() {
				return nil, fieldError("Dialogue.Opaque.DirectReference", ErrUnexpectedDialoguePDU)
			}
		}
		e, err := encodeExternal(*d.Opaque, "Dialogue.Opaque")
		if err != nil {
			return nil, err
		}
		w := wire.DialoguePortion(e)
		return &w, nil
	}
	var pdu wire.DialoguePDU
	var data []byte
	var err error
	asid := wire.DialogueAsId()
	switch {
	case d.Request != nil:
		v, path := d.Request, "Dialogue.Request"
		acn, e := encodeOID(v.ApplicationContextName, path+".ApplicationContextName")
		if e != nil {
			return nil, e
		}
		ui, e := encodeExternals(v.UserInformation, path+".UserInformation")
		if e != nil {
			return nil, e
		}
		w := wire.AARQApdu{ProtocolVersion: cloneBitsPointer(v.ProtocolVersion), ApplicationContextName: acn}
		if ui != nil {
			w.UserInformation = &wire.AARQApduUserInformation{Values: ui}
		}
		pdu = wire.NewDialoguePDUDialogueRequest(w)
	case d.Response != nil:
		v, path := d.Response, "Dialogue.Response"
		acn, e := encodeOID(v.ApplicationContextName, path+".ApplicationContextName")
		if e != nil {
			return nil, e
		}
		ui, e := encodeExternals(v.UserInformation, path+".UserInformation")
		if e != nil {
			return nil, e
		}
		w := wire.AAREApdu{ProtocolVersion: cloneBitsPointer(v.ProtocolVersion), ApplicationContextName: acn, Result: v.Result}
		if ui != nil {
			w.UserInformation = &wire.AAREApduUserInformation{Values: ui}
		}
		if v.ResultSourceDiagnostic.DialogueServiceUser != nil {
			w.ResultSourceDiagnostic = wire.NewAssociateSourceDiagnosticDialogueServiceUser(*v.ResultSourceDiagnostic.DialogueServiceUser)
		} else {
			w.ResultSourceDiagnostic = wire.NewAssociateSourceDiagnosticDialogueServiceProvider(*v.ResultSourceDiagnostic.DialogueServiceProvider)
		}
		pdu = wire.NewDialoguePDUDialogueResponse(w)
	case d.Abort != nil:
		v, path := d.Abort, "Dialogue.Abort"
		ui, e := encodeExternals(v.UserInformation, path+".UserInformation")
		if e != nil {
			return nil, e
		}
		w := wire.ABRTApdu{AbortSource: v.AbortSource}
		if ui != nil {
			w.UserInformation = &wire.ABRTApduUserInformation{Values: ui}
		}
		pdu = wire.NewDialoguePDUDialogueAbort(w)
	case d.Unidirectional != nil:
		v, path := d.Unidirectional, "Dialogue.Unidirectional"
		acn, e := encodeOID(v.ApplicationContextName, path+".ApplicationContextName")
		if e != nil {
			return nil, e
		}
		ui, e := encodeExternals(v.UserInformation, path+".UserInformation")
		if e != nil {
			return nil, e
		}
		w := wire.AUDTApdu{ProtocolVersion: cloneBitsPointer(v.ProtocolVersion), ApplicationContextName: acn}
		if ui != nil {
			w.UserInformation = &wire.AUDTApduUserInformation{Values: ui}
		}
		uni := wire.NewUniDialoguePDUUnidialoguePDU(w)
		data, err = uni.MarshalBER()
		asid = wire.UniDialogueAsId()
	}
	if data == nil && err == nil {
		data, err = pdu.MarshalBER()
	}
	if err != nil {
		return nil, err
	}
	e := wire.DialoguePortion(runtime.External{DirectReference: asid, Encoding: runtime.ExternalSingleASN1Type, SingleASN1Type: runtime.RawValue{Bytes: data}})
	return &e, nil
}

func encodeOID(v OID, path string) (runtime.ObjectIdentifier, error) {
	arcs, err := parseOID(string(v))
	return arcs, fieldError(path, err)
}

// ITU-T X.690 (02/2021) clause 8.18: EXTERNAL selects exactly one encoding.
// Identification constraints are enforced by the codec's EncodeExternal.
func encodeExternal(v External, path string) (runtime.External, error) {
	otherSingle := len(v.SingleASN1Type) != 0
	otherOctets := len(v.OctetAligned) != 0
	otherBits := v.Arbitrary.BitLength != 0 || len(v.Arbitrary.Bytes) != 0
	valid := false
	switch v.Encoding {
	case runtime.ExternalSingleASN1Type:
		valid = !otherOctets && !otherBits
	case runtime.ExternalOctetAligned:
		valid = !otherSingle && !otherBits
	case runtime.ExternalArbitrary:
		valid = !otherSingle && !otherOctets
	}
	if !valid {
		return runtime.External{}, fieldError(path, ErrExternalEncoding)
	}
	w := runtime.External{IndirectReference: cloneBigInt(v.IndirectReference), DataValueDescriptor: clonePointer(v.DataValueDescriptor), Encoding: v.Encoding,
		SingleASN1Type: runtime.RawValue{Bytes: slices.Clone(v.SingleASN1Type)}, OctetAligned: slices.Clone(v.OctetAligned), Arbitrary: cloneBits(v.Arbitrary)}
	if v.DirectReference != "" {
		arcs, err := encodeOID(v.DirectReference, path+".DirectReference")
		if err != nil {
			return w, err
		}
		w.DirectReference = arcs
	}
	return w, nil
}

func encodeExternals(v []External, path string) ([]runtime.External, error) {
	if v == nil {
		return nil, nil
	}
	out := make([]runtime.External, len(v))
	for i, e := range v {
		w, err := encodeExternal(e, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		out[i] = w
	}
	return out, nil
}
