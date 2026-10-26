package tcap

import (
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

// Component is one component of the component portion (ITU-T Q.773 (06/97)
// clause 3.1 and Annex A). Exactly one field is set.
type Component struct {
	Invoke              *Invoke
	ReturnResultLast    *ReturnResult
	ReturnResultNotLast *ReturnResult
	ReturnError         *ReturnError
	Reject              *Reject
}

// Invoke requests an operation (Q.773 Table 15).
//
// InvokeID and a present LinkedID are component IDs, one octet long, so in
// the range -128..127 (Q.773 clause 4.2.2.2). A nil LinkedID omits it.
// Parameter is the complete BER encoding of one value, the operation
// argument; nil omits it.
type Invoke struct {
	InvokeID  int64
	LinkedID  *int64
	OpCode    Code
	Parameter []byte
}

// ReturnResult returns the result of an operation (Q.773 Table 16). It is
// carried as a Return Result (Last) or a Return Result (Not Last) component.
// A nil Result omits the result sequence, as when the operation returns no
// result value.
type ReturnResult struct {
	InvokeID int64
	Result   *Result
}

// Result is the result sequence of a Return Result: the operation code and
// the complete BER encoding of one value, the result. Both are mandatory
// (Q.773 Table 16 note b).
type Result struct {
	OpCode    Code
	Parameter []byte
}

// ReturnError reports that an operation failed (Q.773 Table 17). Parameter
// is the complete BER encoding of one value, the error parameter; nil omits
// it.
type ReturnError struct {
	InvokeID  int64
	ErrorCode Code
	Parameter []byte
}

// Reject reports a malformed or unexpected component (Q.773 Table 18). A nil
// InvokeID means the invoke ID of the rejected component is not available
// and is encoded as NULL.
type Reject struct {
	InvokeID *int64
	Problem  Problem
}

// Problem is the problem code of a Reject (Q.773 clause 4.2.2.6). Exactly one
// field is set.
type Problem struct {
	General      *GeneralProblem
	Invoke       *InvokeProblem
	ReturnResult *ReturnResultProblem
	ReturnError  *ReturnErrorProblem
}

// GeneralProblem is the problem code of a Reject for a general problem
// (ITU-T X.880 (07/94), Remote-Operations-Generic-ROS-PDUs). Build one with
// NewGeneralProblem and compare one with AsInt64 against these constants.
type GeneralProblem = wire.GeneralProblem

// The named numbers of GeneralProblem.
const (
	GeneralProblemUnrecognizedPDU    = wire.GeneralProblemUnrecognizedPDU
	GeneralProblemMistypedPDU        = wire.GeneralProblemMistypedPDU
	GeneralProblemBadlyStructuredPDU = wire.GeneralProblemBadlyStructuredPDU
)

// NewGeneralProblem returns the GeneralProblem with the given value.
func NewGeneralProblem(value int64) GeneralProblem {
	return wire.NewGeneralProblemInt64(value)
}

// InvokeProblem is the problem code of a Reject for an Invoke (X.880
// Remote-Operations-Generic-ROS-PDUs). Build one with NewInvokeProblem and
// compare one with AsInt64 against these constants.
type InvokeProblem = wire.InvokeProblem

// The named numbers of InvokeProblem.
const (
	InvokeProblemDuplicateInvocation       = wire.InvokeProblemDuplicateInvocation
	InvokeProblemUnrecognizedOperation     = wire.InvokeProblemUnrecognizedOperation
	InvokeProblemMistypedArgument          = wire.InvokeProblemMistypedArgument
	InvokeProblemResourceLimitation        = wire.InvokeProblemResourceLimitation
	InvokeProblemReleaseInProgress         = wire.InvokeProblemReleaseInProgress
	InvokeProblemUnrecognizedLinkedId      = wire.InvokeProblemUnrecognizedLinkedId
	InvokeProblemLinkedResponseUnexpected  = wire.InvokeProblemLinkedResponseUnexpected
	InvokeProblemUnexpectedLinkedOperation = wire.InvokeProblemUnexpectedLinkedOperation
)

// NewInvokeProblem returns the InvokeProblem with the given value.
func NewInvokeProblem(value int64) InvokeProblem {
	return wire.NewInvokeProblemInt64(value)
}

// ReturnResultProblem is the problem code of a Reject for a Return Result
// (X.880 Remote-Operations-Generic-ROS-PDUs). Build one with
// NewReturnResultProblem and compare one with AsInt64 against these
// constants.
type ReturnResultProblem = wire.ReturnResultProblem

// The named numbers of ReturnResultProblem.
const (
	ReturnResultProblemUnrecognizedInvocation   = wire.ReturnResultProblemUnrecognizedInvocation
	ReturnResultProblemResultResponseUnexpected = wire.ReturnResultProblemResultResponseUnexpected
	ReturnResultProblemMistypedResult           = wire.ReturnResultProblemMistypedResult
)

// NewReturnResultProblem returns the ReturnResultProblem with the given value.
func NewReturnResultProblem(value int64) ReturnResultProblem {
	return wire.NewReturnResultProblemInt64(value)
}

// ReturnErrorProblem is the problem code of a Reject for a Return Error
// (X.880 Remote-Operations-Generic-ROS-PDUs). Build one with
// NewReturnErrorProblem and compare one with AsInt64 against these
// constants.
type ReturnErrorProblem = wire.ReturnErrorProblem

// The named numbers of ReturnErrorProblem.
const (
	ReturnErrorProblemUnrecognizedInvocation  = wire.ReturnErrorProblemUnrecognizedInvocation
	ReturnErrorProblemErrorResponseUnexpected = wire.ReturnErrorProblemErrorResponseUnexpected
	ReturnErrorProblemUnrecognizedError       = wire.ReturnErrorProblemUnrecognizedError
	ReturnErrorProblemUnexpectedError         = wire.ReturnErrorProblemUnexpectedError
	ReturnErrorProblemMistypedParameter       = wire.ReturnErrorProblemMistypedParameter
)

// NewReturnErrorProblem returns the ReturnErrorProblem with the given value.
func NewReturnErrorProblem(value int64) ReturnErrorProblem {
	return wire.NewReturnErrorProblemInt64(value)
}

// Code is an operation code or an error code: a LocalCode or a GlobalCode
// (Q.773 clauses 4.2.2.3 and 4.2.2.5; ITU-T X.880 (07/94) Code). A nil Code
// is missing.
type Code interface {
	isCode()
}

// LocalCode is a local operation or error code, an INTEGER.
type LocalCode int64

func (LocalCode) isCode() {}

// GlobalCode is a global operation or error code, an OBJECT IDENTIFIER.
type GlobalCode OID

func (GlobalCode) isCode() {}
