package tcap

import (
	"math/big"
	"slices"

	"github.com/gomaja/go-asn1/runtime"
)

// ITU-T Q.773 (06/97) clause 4.2.3 carries user data without transferring ownership.
func clonePointer[T any](v *T) *T {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func cloneBigInt(v *big.Int) *big.Int {
	if v == nil {
		return nil
	}
	return new(big.Int).Set(v)
}

// cloneBits leaves the value as given. The encoders currently treat bits after
// BitLength differently: https://github.com/gomaja/go-asn1/issues/154.
// ITU-T X.690 (02/2021) clause 8.6.2 governs the encoded BIT STRING.
func cloneBits(v runtime.BitString) runtime.BitString {
	v.Bytes = slices.Clone(v.Bytes)
	return v
}

func cloneBitsPointer(v *runtime.BitString) *runtime.BitString {
	if v == nil {
		return nil
	}
	c := cloneBits(*v)
	return &c
}

func cloneExternal(v External) External {
	v.IndirectReference = cloneBigInt(v.IndirectReference)
	v.DataValueDescriptor = clonePointer(v.DataValueDescriptor)
	v.SingleASN1Type = slices.Clone(v.SingleASN1Type)
	v.OctetAligned = slices.Clone(v.OctetAligned)
	v.Arbitrary = cloneBits(v.Arbitrary)
	return v
}

func cloneExternals(v []External) []External {
	if v == nil {
		return nil
	}
	out := make([]External, len(v))
	for i, e := range v {
		out[i] = cloneExternal(e)
	}
	return out
}

func cloneDiagnostic(v ResultSourceDiagnostic) ResultSourceDiagnostic {
	return ResultSourceDiagnostic{DialogueServiceUser: clonePointer(v.DialogueServiceUser), DialogueServiceProvider: clonePointer(v.DialogueServiceProvider)}
}
