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
	violations *ber.ViolationLog
	limits     *ber.DecodeLimits
}

// WithConstraintTolerance makes Parse accept values outside their ASN.1
// constraints, such as a transaction ID longer than 4 octets or an invoke ID
// outside -128..127, and record each violation in log. The violations are
// recorded only if Parse succeeds. Encoding errors and the rules for dialogue
// PDUs still apply, and Marshal stays strict: a message parsed with tolerated
// violations does not marshal until they are corrected. log must not be nil.
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
	tolerance := false
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil ParseOption", ErrInvalidParseOption)
		}
		if opt, ok := opt.(toleranceParseOption); ok && opt.log == nil {
			return nil, fmt.Errorf("%w: nil constraint violation log", ErrInvalidParseOption)
		}
		opt.applyParseOption(&config)
		if _, ok := opt.(toleranceParseOption); ok {
			tolerance = true
		}
	}
	var decodeOpts []ber.DecodeOption
	maxElements := ber.DefaultDecodeLimits().MaxElements
	if tolerance {
		decodeOpts = append(decodeOpts, ber.WithConstraintTolerance(config.violations))
	}
	if config.limits != nil {
		decodeOpts = append(decodeOpts, ber.WithDecodeLimits(*config.limits))
		if config.limits.MaxElements != 0 {
			maxElements = config.limits.MaxElements
		}
	}
	// go-asn1 validates decode options when a decoder starts and exports no
	// separate check (https://github.com/gomaja/go-asn1/issues/141); decoding
	// empty content runs it without reading data.
	if _, err := ber.DecodeSequenceChildren(nil, decodeOpts...); err != nil {
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
		pe := inspectFailure(data, decodeOpts, errors.Is(err, ber.ErrResourceLimit), maxElements)
		if errors.Is(pe.Err, ErrUnrecognizedMessageType) || errors.Is(pe.Err, ErrUnrecognizedComponent) {
			err = joinErrors(err, pe.Err)
		}
		pe.Err = err
		return nil, pe
	}
	m, pe := decodeMessage(&w, decodeOpts)
	if pe != nil {
		if errors.Is(pe.Err, ber.ErrResourceLimit) {
			failure := inspectFailure(data, decodeOpts, true, maxElements)
			failure.Err = pe.Err
			return nil, failure
		}
		if pe.ComponentIndex >= 0 {
			pe.InvokeID, pe.ComponentType = inspectComponent(data, pe.ComponentIndex, decodeOpts)
		}
		return nil, pe
	}
	return m, nil
}

type toleranceParseOption struct{ log *ber.ViolationLog }

func (o toleranceParseOption) applyParseOption(c *parseConfig) { c.violations = o.log }

type limitsParseOption struct{ limits ber.DecodeLimits }

func (o limitsParseOption) applyParseOption(c *parseConfig) { c.limits = &o.limits }
