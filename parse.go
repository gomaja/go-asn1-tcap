package tcap

import (
	"errors"

	"github.com/gomaja/go-asn1/runtime/ber"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
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
	return toleranceParseOption{log}
}

// WithDecodeLimits replaces the decoding limits of go-asn1, which bound the
// work spent on untrusted input. Zero fields keep the defaults of
// ber.DefaultDecodeLimits.
func WithDecodeLimits(limits ber.DecodeLimits) ParseOption {
	return limitsParseOption{limits}
}

// Parse decodes one complete TCAP message.
//
// It returns a *Begin, *Continue, *End, *Abort or *Unidirectional. Every
// error is a *ParseError. The returned message does not alias data.
func Parse(data []byte, opts ...ParseOption) (message Message, returnErr error) {
	if len(data) == 0 {
		return nil, &ParseError{Portion: PortionTransaction, ComponentIndex: -1, Err: ErrEmptyData}
	}
	config := parseConfig{}
	tolerance := false
	for _, opt := range opts {
		if opt == nil {
			return nil, &ParseError{Portion: PortionTransaction, ComponentIndex: -1, Err: ber.ErrInvalidValue}
		}
		opt.applyParseOption(&config)
		if _, ok := opt.(toleranceParseOption); ok {
			tolerance = true
		}
	}
	var decodeOpts []ber.DecodeOption
	if tolerance {
		decodeOpts = append(decodeOpts, ber.WithConstraintTolerance(config.violations))
	}
	if config.limits != nil {
		decodeOpts = append(decodeOpts, ber.WithDecodeLimits(*config.limits))
	}
	// Stage reports across codec decoding, receiver rules and the Q.773 profile.
	decodeOpts, finish := ber.StageDecodeReports(decodeOpts)
	defer func() { finish(returnErr == nil) }()
	var w wire.TCMessage
	if err := w.UnmarshalBER(data, decodeOpts...); err != nil {
		pe := inspectFailure(data, decodeOpts)
		if errors.Is(pe.Err, ErrUnrecognizedMessageType) || errors.Is(pe.Err, ErrUnrecognizedComponent) {
			err = errors.Join(err, pe.Err)
		}
		pe.Err = err
		return nil, pe
	}
	m, pe := decodeMessage(&w, decodeOpts)
	if pe != nil {
		if pe.ComponentIndex >= 0 {
			pe.InvokeID = inspectComponentID(data, pe.ComponentIndex, decodeOpts)
		}
		return nil, pe
	}
	if failure := checkProfile(data, decodeOpts); failure != nil {
		pe := inspectFailure(data, decodeOpts)
		pe.Portion, pe.ComponentIndex, pe.Err = failure.portion, failure.index, failure.err
		if failure.portion == PortionComponent {
			pe.InvokeID = inspectComponentID(data, failure.index, decodeOpts)
			d, c := messagePortions(m)
			pe.Dialogue = d
			if failure.index >= 0 {
				pe.Components = c[:failure.index]
			} else {
				pe.Components = nil
			}
		} else {
			pe.InvokeID, pe.Dialogue, pe.Components = nil, nil, nil
		}
		return nil, pe
	}
	return m, nil
}

type toleranceParseOption struct{ log *ber.ViolationLog }

func (o toleranceParseOption) applyParseOption(c *parseConfig) { c.violations = o.log }

type limitsParseOption struct{ limits ber.DecodeLimits }

func (o limitsParseOption) applyParseOption(c *parseConfig) { c.limits = &o.limits }

func messagePortions(m Message) (*Dialogue, []Component) {
	switch m := m.(type) {
	case *Begin:
		return m.Dialogue, m.Components
	case *Continue:
		return m.Dialogue, m.Components
	case *End:
		return m.Dialogue, m.Components
	case *Unidirectional:
		return m.Dialogue, m.Components
	case *Abort:
		return m.Dialogue, nil
	}
	return nil, nil
}
