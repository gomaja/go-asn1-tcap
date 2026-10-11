package camel

import "github.com/gomaja/go-asn1-tcap"

// Error codes (local values of the error code in a Return Error) of 3GPP TS
// 29.078 V19.0.0 clause 5.4, module CAP-errorcodes.
const (
	ErrorCodeCanceled                    tcap.LocalCode = 0  // errcode-canceled
	ErrorCodeCancelFailed                tcap.LocalCode = 1  // errcode-cancelFailed
	ErrorCodeETCFailed                   tcap.LocalCode = 3  // errcode-eTCFailed
	ErrorCodeImproperCallerResponse      tcap.LocalCode = 4  // errcode-improperCallerResponse
	ErrorCodeMissingCustomerRecord       tcap.LocalCode = 6  // errcode-missingCustomerRecord
	ErrorCodeMissingParameter            tcap.LocalCode = 7  // errcode-missingParameter
	ErrorCodeParameterOutOfRange         tcap.LocalCode = 8  // errcode-parameterOutOfRange
	ErrorCodeRequestedInfoError          tcap.LocalCode = 10 // errcode-requestedInfoError
	ErrorCodeSystemFailure               tcap.LocalCode = 11 // errcode-systemFailure
	ErrorCodeTaskRefused                 tcap.LocalCode = 12 // errcode-taskRefused
	ErrorCodeUnavailableResource         tcap.LocalCode = 13 // errcode-unavailableResource
	ErrorCodeUnexpectedComponentSequence tcap.LocalCode = 14 // errcode-unexpectedComponentSequence
	ErrorCodeUnexpectedDataValue         tcap.LocalCode = 15 // errcode-unexpectedDataValue
	ErrorCodeUnexpectedParameter         tcap.LocalCode = 16 // errcode-unexpectedParameter
	ErrorCodeUnknownLegID                tcap.LocalCode = 17 // errcode-unknownLegID
	ErrorCodeUnknownPDPID                tcap.LocalCode = 50 // errcode-unknownPDPID
	ErrorCodeUnknownCSID                 tcap.LocalCode = 51 // errcode-unknownCSID
)
