package tcap

import (
	"github.com/gomaja/go-asn1/runtime/ber"
)

// ParseOption configures Parse.
type ParseOption interface {
	applyParseOption(*parseConfig)
}

type parseConfig struct {
	violations *ber.ViolationLog
	limits     *ber.DecodeLimits
}

// WithConstraintTolerance makes Parse accept values outside their ASN.1
// constraints, such as a transaction ID longer than 4 octets or an invoke ID
// outside -128..127, and record each violation in log. The violations are
// recorded only if Parse succeeds. Encoding errors, the encoding restrictions
// of ITU-T Q.773 (06/97) clause 4.1.1 and the rules for dialogue PDUs still
// apply, and Marshal stays strict: a message parsed with tolerated violations
// does not marshal until they are corrected.
func WithConstraintTolerance(log *ber.ViolationLog) ParseOption {
	panic("unimplemented")
}

// WithDecodeLimits replaces the decoding limits of go-asn1, which bound the
// work spent on untrusted input. Zero fields keep the defaults of
// ber.DefaultDecodeLimits.
func WithDecodeLimits(limits ber.DecodeLimits) ParseOption {
	panic("unimplemented")
}

// Parse decodes one complete TCAP message.
//
// It returns a *Begin, *Continue, *End, *Abort or *Unidirectional. Every
// error is a *ParseError. The returned message does not alias data.
func Parse(data []byte, opts ...ParseOption) (Message, error) {
	panic("unimplemented")
}
