package tcap

import (
	"bytes"
	"slices"

	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

type profileFailure struct {
	portion Portion
	index   int
	err     error
}

// ITU-T Q.773 (06/97) clause 4.1.1 requires minimal definite lengths.
// Clause 4.1.2.3 permits indefinite lengths for constructed elements.
func checkLength(data []byte) error {
	_, tagLen, err := ber.DecodeTag(data)
	if err != nil {
		return err
	}
	length, indefinite, n, err := ber.DecodeLength(data[tagLen:])
	if err != nil {
		return err
	}
	if !indefinite && !bytes.Equal(data[tagLen:tagLen+n], ber.EncodeLength(length)) {
		return ErrNonMinimalLength
	}
	return nil
}

type profileNode struct {
	tag   tag.Tag
	data  []byte
	value []byte
}

func profileTLV(data []byte, opts []ber.DecodeOption) (profileNode, int, error) {
	t, n, v, err := ber.DecodeTLV(data, opts...)
	if err != nil {
		return profileNode{}, 0, err
	}
	node := profileNode{tag: t, data: data[:n], value: v}
	return node, n, checkLength(node.data)
}

func profileChildren(data []byte, opts []ber.DecodeOption, visit func(profileNode) error) error {
	for len(data) > 0 {
		child, n, err := profileTLV(data, opts)
		if err != nil {
			return err
		}
		if err := visit(child); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// Q.773 clause 4.1.1 applies to TCAP-owned values; opaque contents are not walked.
func checkProfile(data []byte, opts []ber.DecodeOption) *profileFailure {
	root, _, err := profileTLV(data, opts)
	if err != nil {
		return &profileFailure{PortionTransaction, -1, err}
	}
	children := root.value
	for len(children) > 0 {
		// Decode before checking length so the correct portion remains available.
		t, n, value, err := ber.DecodeTLV(children, opts...)
		if err != nil {
			return &profileFailure{PortionTransaction, -1, err}
		}
		child := profileNode{t, children[:n], value}
		portion := PortionTransaction
		if t.Class == tag.ClassApplication && t.Number == 11 {
			portion = PortionDialogue
		}
		if t.Class == tag.ClassApplication && t.Number == 12 {
			portion = PortionComponent
		}
		if err := checkLength(child.data); err != nil {
			return &profileFailure{portion, -1, err}
		}
		switch {
		case t.Class == tag.ClassApplication && (t.Number == 8 || t.Number == 9):
			if t.Constructed {
				return &profileFailure{portion, -1, ErrConstructedString}
			}
		case portion == PortionDialogue:
			err = profileChildren(value, opts, func(e profileNode) error { return profileExternal(e, true, opts) })
		case portion == PortionComponent:
			index := 0
			for len(value) > 0 {
				c, n, e := profileTLV(value, opts)
				if e == nil {
					e = profileComponent(c, opts)
				}
				if e != nil {
					return &profileFailure{portion, index, e}
				}
				index++
				value = value[n:]
			}
		}
		if err != nil {
			return &profileFailure{portion, -1, err}
		}
		children = children[n:]
	}
	return nil
}

// Q.773 Tables 15-18: only the parameter's outer TLV belongs to TCAP.
func profileComponent(c profileNode, opts []ber.DecodeOption) error {
	index := 0
	return profileChildren(c.value, opts, func(child profileNode) error {
		defer func() { index++ }()
		if index == 0 {
			return nil
		}
		switch c.tag.Number {
		case 2, 7: // ReturnResult: ID, optional SEQUENCE {code, opaque result}.
			return profileChildren(child.value, opts, func(profileNode) error { return nil })
		}
		return nil
	})
}

// Q.773 Tables 30-37 and X.690 clause 8.18: EXTERNAL's encoding fields are
// owned; an unknown abstract syntax's data value remains opaque.
func profileExternal(e profileNode, dialogue bool, opts []ber.DecodeOption) error {
	known := false
	return profileChildren(e.value, opts, func(child profileNode) error {
		if child.tag.Class == tag.ClassUniversal && child.tag.Number == tag.TagObjectID && dialogue {
			oid, _, err := ber.DecodeObjectIdentifier(child.data, opts...)
			if err != nil {
				return err
			}
			known = slices.Equal(oid, wire.DialogueAsId()) || slices.Equal(oid, wire.UniDialogueAsId())
		}
		if child.tag.Class != tag.ClassContextSpecific {
			return profileOwned(child, opts)
		}
		switch child.tag.Number {
		case 0:
			return profileChildren(child.value, opts, func(inner profileNode) error {
				if known {
					return profilePDU(inner, opts)
				}
				return nil
			})
		case 1, 2:
			if child.tag.Constructed {
				return ErrConstructedString
			}
			if known {
				data := child.value
				if child.tag.Number == 2 {
					if len(data) == 0 || data[0] != 0 {
						return ErrExternalEncoding
					}
					data = data[1:]
				}
				inner, _, err := profileTLV(data, opts)
				if err != nil {
					return err
				}
				return profilePDU(inner, opts)
			}
		}
		return nil
	})
}

// Q.773 clause 3.2: user-information is a SEQUENCE OF opaque EXTERNALs.
func profilePDU(pdu profileNode, opts []ber.DecodeOption) error {
	return profileChildren(pdu.value, opts, func(field profileNode) error {
		if field.tag.Class == tag.ClassContextSpecific && field.tag.Number == 30 {
			return profileChildren(field.value, opts, func(e profileNode) error { return profileExternal(e, false, opts) })
		}
		if field.tag.Class == tag.ClassContextSpecific && field.tag.Number == 0 && (pdu.tag.Number == 0 || pdu.tag.Number == 1) {
			if field.tag.Constructed {
				return ErrConstructedString
			}
		}
		return profileOwned(field, opts)
	})
}

func profileOwned(node profileNode, opts []ber.DecodeOption) error {
	if node.tag.Class == tag.ClassUniversal && (node.tag.Number == tag.TagOctetString || node.tag.Number == tag.TagBitString) && node.tag.Constructed {
		return ErrConstructedString
	}
	if node.tag.Constructed {
		return profileChildren(node.value, opts, func(child profileNode) error { return profileOwned(child, opts) })
	}
	return nil
}
