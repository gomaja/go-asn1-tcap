package tcap

import (
	"errors"
	"fmt"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// ViolationLog records what Parse accepts under WithTolerance. A zero value
// is ready for use, and Snapshot returns the records in the order they were
// reported. It is the codec's own type, named here so that a caller needs no
// import of go-asn1; so are Violation, ViolationKind, RuleRef and
// DecodeLimits.
type ViolationLog = ber.ViolationLog

// Violation is one record of a ViolationLog: the kind and rule that were
// broken, where (Path, Offset and ChildIndexes), and what was observed.
type Violation = ber.Violation

// ViolationKind tells an ASN.1 constraint from a protocol text rule.
type ViolationKind = ber.ViolationKind

// The kinds of a Violation.
const (
	// ASN1Constraint is a constraint of the ASN.1 (ITU-T X.680 (02/2021)
	// clause 51).
	ASN1Constraint = ber.ASN1Constraint
	// ProtocolRule is a protocol text rule, such as ITU-T Q.773 (06/97)
	// clause 4.1.1.
	ProtocolRule = ber.ProtocolRule
)

// RuleRef names the document, edition and clause of a broken rule.
type RuleRef = ber.RuleRef

// DecodeLimits bounds the work Parse spends on its input; see
// WithDecodeLimits.
type DecodeLimits = ber.DecodeLimits

// DefaultDecodeLimits returns the limits Parse uses when WithDecodeLimits is
// not given.
func DefaultDecodeLimits() DecodeLimits { return ber.DefaultDecodeLimits() }

// ParseOption configures Parse.
type ParseOption interface {
	applyParseOption(*parseConfig)
}

type parseConfig struct {
	log      *ViolationLog
	tolerant bool
	limits   *DecodeLimits
}

// WithTolerance makes Parse accept other valid BER representations and
// values outside their ASN.1 constraints, recording each violation in log
// only if Parse succeeds. BER encoding errors and the rules this package
// applies itself, such as the dialogue rules of ITU-T Q.774 (06/97) Table 3,
// apply in both modes. Marshal stays strict: it encodes TCAP's own fields
// afresh, so a representation tolerated there needs no correction, and it
// keeps parameters and EXTERNAL contents, the TC-user's syntax, as received.
// log must not be nil.
// If supplied more than once, the last WithTolerance wins.
func WithTolerance(log *ViolationLog) ParseOption {
	return toleranceParseOption{log}
}

// WithDecodeLimits replaces the decoding limits of go-asn1, which bound the
// work spent on untrusted input. Zero fields keep the defaults of
// DefaultDecodeLimits.
func WithDecodeLimits(limits DecodeLimits) ParseOption {
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
		return nil, &ParseError{Portion: PortionTransaction, ComponentIndex: -1, Err: ErrEmptyData,
			pAbortCause: PAbortCauseBadlyFormattedTransactionPortion, pAbortCauseSet: true}
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
