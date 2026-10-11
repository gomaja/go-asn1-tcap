package tcap

import (
	"math"
	"strconv"
	"strings"
)

// OID is an OBJECT IDENTIFIER in canonical dotted-decimal form, for example
// "0.4.0.0.1.0.20.3": decimal arcs without signs, spaces or leading zeros,
// separated by single dots. OIDs are comparable with == and can be declared
// as constants. A valid OID has at least two arcs, a first arc of 0, 1 or 2,
// and a second arc of at most 39 when the first arc is 0 or 1 (ITU-T X.690
// (02/2021) clause 8.19.4).
//
// A conversion such as OID(s) does not validate s; Marshal validates every
// OID it encodes.
type OID string

// ParseOID validates s and returns it as an OID. It returns ErrInvalidOID if
// s is not a valid OID in canonical form, and ErrUnrepresentableValue if an
// arc does not fit in 64 bits.
func ParseOID(s string) (OID, error) {
	if _, err := OID(s).Arcs(); err != nil {
		return "", err
	}
	return OID(s), nil
}

// OIDFromArcs returns the OID with the given arcs. It returns ErrInvalidOID
// if the arcs do not form a valid OID, and ErrUnrepresentableValue if the
// first two arcs do not fit in one 64-bit subidentifier.
func OIDFromArcs(arcs ...uint64) (OID, error) {
	if err := validateArcs(arcs); err != nil {
		return "", err
	}
	parts := make([]string, len(arcs))
	for i, arc := range arcs {
		parts[i] = strconv.FormatUint(arc, 10)
	}
	return OID(strings.Join(parts, ".")), nil
}

// Arcs returns the arcs of the OID. It returns the errors of ParseOID.
func (o OID) Arcs() ([]uint64, error) {
	parts := strings.Split(string(o), ".")
	if len(parts) < 2 {
		return nil, ErrInvalidOID
	}
	arcs := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return nil, ErrInvalidOID
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return nil, ErrInvalidOID
			}
		}
		arc, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, ErrUnrepresentableValue
		}
		arcs[i] = arc
	}
	if err := validateArcs(arcs); err != nil {
		return nil, err
	}
	return arcs, nil
}

// ITU-T X.690 (02/2021) clause 8.19.4 combines the first two arcs.
func validateArcs(arcs []uint64) error {
	if len(arcs) < 2 || arcs[0] > 2 || arcs[0] < 2 && arcs[1] > 39 {
		return ErrInvalidOID
	}
	if arcs[1] > math.MaxUint64-arcs[0]*40 {
		return ErrUnrepresentableValue
	}
	return nil
}
