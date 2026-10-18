package tcap

import (
	"errors"
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
)

// OID is an OBJECT IDENTIFIER in canonical dotted-decimal form, for example
// "0.4.0.0.1.0.20.3". OIDs compare with == and can be constants. Conversion
// with OID(s) does not validate s; Marshal validates every OID it encodes.
// Arcs have no fixed width (ITU-T X.690 (02/2021) clause 8.19).
type OID string

// ParseOID returns s as an OID after validation by runtime.ParseObjectIdentifier.
// Malformed input wraps ErrInvalidOID; decimal conversion limits return
// runtime.ErrOIDTextLimit. Arcs larger than uint64 are valid.
func ParseOID(s string) (OID, error) {
	if _, err := parseOID(s); err != nil {
		return "", err
	}
	return OID(s), nil
}

// OIDFromArcs returns the canonical OID with the given uint64 arcs. Invalid
// root arcs wrap ErrInvalidOID. Combining the first two arcs does not impose
// a uint64 limit (ITU-T X.690 (02/2021) clause 8.19.4).
// Decimal conversion limits return runtime.ErrOIDTextLimit.
func OIDFromArcs(arcs ...uint64) (OID, error) {
	v, err := runtime.ObjectIdentifierFromArcs(arcs...)
	if err != nil {
		return "", oidError(err)
	}
	return decodeOID(v)
}

// Arcs returns an owned uint64 view. Malformed input wraps ErrInvalidOID;
// decimal conversion limits return runtime.ErrOIDTextLimit. A valid OID with
// an arc larger than uint64 returns ErrUnrepresentableValue.
func (o OID) Arcs() ([]uint64, error) {
	v, err := parseOID(string(o))
	if err != nil {
		return nil, err
	}
	arcs, ok := v.Arcs()
	if !ok {
		return nil, ErrUnrepresentableValue
	}
	return arcs, nil
}

func parseOID(s string) (runtime.ObjectIdentifier, error) {
	v, err := runtime.ParseObjectIdentifier(s)
	return v, oidError(err)
}

func oidError(err error) error {
	if errors.Is(err, runtime.ErrInvalidOID) {
		return fmt.Errorf("%w: %w", ErrInvalidOID, err)
	}
	return err
}

func decodeOID(v runtime.ObjectIdentifier) (OID, error) {
	s, err := v.StringChecked()
	return OID(s), oidError(err)
}
