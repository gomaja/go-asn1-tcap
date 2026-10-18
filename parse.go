package tcap

import (
	"errors"
	"fmt"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
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

// WithTolerance makes Parse accept other valid BER representations and
// values outside their ASN.1 constraints, recording each violation in log
// only if Parse succeeds. BER structure errors and the rules this package
// applies itself, such as the dialogue rules of ITU-T Q.774 (06/97) Table 3,
// apply in both modes. Marshal stays strict: parameters and EXTERNAL
// single-ASN1-type contents that violate Q.773 clause 4.1.1 must be
// corrected before encoding. log must not be nil.
// If supplied more than once, the last WithTolerance wins.
func WithTolerance(log *ber.ViolationLog) ParseOption {
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
// error wrapping ErrInvalidParseOption. The returned message and error
// context do not alias data.
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
		decodeOpts = append(decodeOpts, ber.WithTolerance(config.log))
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
		pe := inspectFailure(data, decodeOpts, errors.Is(err, ber.ErrResourceLimit), limits, err)
		// Err describes the element that Portion and ComponentIndex
		// designate: a dialogue portion or component that inspection found
		// failing, or else the message failure reported by the codec.
		if pe.Portion == PortionTransaction || pe.Err == nil {
			pe.Err = joinErrors(pe.Err, err)
		}
		return nil, pe
	}
	m, pe := decodeMessage(&w)
	if pe != nil {
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
