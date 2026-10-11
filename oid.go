package tcap

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
	panic("unimplemented")
}

// OIDFromArcs returns the OID with the given arcs. It returns ErrInvalidOID
// if the arcs do not form a valid OID, and ErrUnrepresentableValue if the
// first two arcs do not fit in one 64-bit subidentifier.
func OIDFromArcs(arcs ...uint64) (OID, error) {
	panic("unimplemented")
}

// Arcs returns the arcs of the OID. It returns the errors of ParseOID.
func (o OID) Arcs() ([]uint64, error) {
	panic("unimplemented")
}
