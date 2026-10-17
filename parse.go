package tcap

import (
	"errors"
	"fmt"

	"github.com/gomaja/go-asn1/runtime/ber"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// ParseOption configures Parse.
type ParseOption interface {
	applyParseOption(*parseConfig)
}

type parseConfig struct {
	log      *ber.ViolationLog
	tolerant bool
	limits   *ber.DecodeLimits
}

// WithConstraintTolerance makes Parse accept values outside their ASN.1
// constraints, such as a transaction ID longer than 4 octets or an invoke ID
// outside -128..127, and record each violation in log. The violations are
// recorded only if Parse succeeds. Encoding errors and the rules for dialogue
// PDUs still apply, and Marshal stays strict: a message parsed with tolerated
// violations does not marshal until they are corrected. log must not be nil.
// If supplied more than once, the last WithConstraintTolerance wins.
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
// error caused by the data is a *ParseError; an invalid option returns an
// error wrapping ErrInvalidParseOption. The returned message does not alias data.
func Parse(data []byte, opts ...ParseOption) (message Message, returnErr error) {
	config := parseConfig{}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil ParseOption", ErrInvalidParseOption)
		}
		opt.applyParseOption(&config)
	}
	var decodeOpts []ber.DecodeOption
	if config.tolerant {
		decodeOpts = append(decodeOpts, ber.WithConstraintTolerance(config.log))
	}
	limits := ber.DefaultDecodeLimits()
	if config.limits != nil {
		decodeOpts = append(decodeOpts, ber.WithDecodeLimits(*config.limits))
		// The nonzero fields replace the defaults, as in ber.WithDecodeLimits.
		if config.limits.MaxDepth != 0 {
			limits.MaxDepth = config.limits.MaxDepth
		}
		if config.limits.MaxElements != 0 {
			limits.MaxElements = config.limits.MaxElements
		}
		if config.limits.MaxWork != 0 {
			limits.MaxWork = config.limits.MaxWork
		}
	}
	if err := ber.ValidateDecodeOptions(decodeOpts...); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidParseOption, err)
	}
	if len(data) == 0 {
		return nil, &ParseError{Portion: PortionTransaction, ComponentIndex: -1, Err: ErrEmptyData}
	}
	// Stage reports across codec decoding and the receiver rules.
	decodeOpts, finish := ber.StageDecodeReports(decodeOpts)
	defer func() { finish(returnErr == nil) }()
	var w wire.TCMessage
	if err := w.UnmarshalBER(data, decodeOpts...); err != nil {
		// Decode limits are operational failures; Q.774 Table 7 context needs
		// only transaction IDs and must not decode the portions again.
		pe := inspectFailure(data, decodeOpts, errors.Is(err, ber.ErrResourceLimit), limits)
		// Err describes the element that Portion and ComponentIndex
		// designate: a dialogue portion or component that inspection found
		// failing, whatever the codec met later, or else the message.
		if pe.Portion == PortionTransaction || pe.Err == nil {
			pe.Err = joinErrors(pe.Err, err)
		}
		return nil, pe
	}
	m, pe := decodeMessage(&w, decodeOpts)
	if pe != nil {
		if errors.Is(pe.Err, ber.ErrResourceLimit) {
			// The complete transaction already decoded within the outer
			// limits; a dialogue PDU inside opaque octets has its own budget.
			pe.Portion, pe.ComponentIndex = PortionTransaction, -1
			pe.InvokeID, pe.Dialogue, pe.Components = nil, nil, nil
			pe.ComponentType = ""
			return nil, pe
		}
		if pe.ComponentIndex >= 0 {
			pe.InvokeID, pe.ComponentType = inspectComponent(data, pe.ComponentIndex, decodeOpts)
		}
		return nil, pe
	}
	return m, nil
}

type toleranceParseOption struct{ log *ber.ViolationLog }

func (o toleranceParseOption) applyParseOption(c *parseConfig) {
	c.log, c.tolerant = o.log, true
}

type limitsParseOption struct{ limits ber.DecodeLimits }

func (o limitsParseOption) applyParseOption(c *parseConfig) { c.limits = &o.limits }
