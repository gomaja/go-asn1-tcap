package tcap

import (
	"errors"
	"fmt"
)

// Sentinel errors for TCAP operations.
var (
	// ErrEmptyData indicates empty or nil data.
	ErrEmptyData = errors.New("empty data provided")

	// ErrInvalidTransactionID indicates invalid transaction ID.
	ErrInvalidTransactionID = errors.New("invalid transaction ID")

	// ErrInvalidInvokeID indicates invalid invoke ID.
	ErrInvalidInvokeID = errors.New("invalid invoke ID")
)

// ParseError represents a parsing error with additional context.
type ParseError struct {
	Op    string // operation that failed
	Field string // field that caused the error
	Err   error  // underlying error
}

func (e *ParseError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("parse error in %s.%s: %v", e.Op, e.Field, e.Err)
	}
	return fmt.Sprintf("parse error in %s: %v", e.Op, e.Err)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// ValidationError represents a validation error with context.
type ValidationError struct {
	Field string
	Value any
	Err   error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for %s (value: %v): %v", e.Field, e.Value, e.Err)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

func newParseError(op, field string, err error) error {
	return &ParseError{Op: op, Field: field, Err: err}
}

func newValidationError(field string, value any, err error) error {
	return &ValidationError{Field: field, Value: value, Err: err}
}
