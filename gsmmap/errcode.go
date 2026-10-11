package gsmmap

import "github.com/gomaja/go-asn1-tcap"

// Error codes (local values of the error code in a Return Error) currently
// defined by 3GPP TS 29.002 V19.1.0 clause 17.6.6, module MAP-Errors.
const (
	ErrorCodeUnknownSubscriber              tcap.LocalCode = 1  // unknownSubscriber
	ErrorCodeUnknownMSC                     tcap.LocalCode = 3  // unknownMSC
	ErrorCodeUnidentifiedSubscriber         tcap.LocalCode = 5  // unidentifiedSubscriber
	ErrorCodeAbsentSubscriberSM             tcap.LocalCode = 6  // absentSubscriberSM
	ErrorCodeUnknownEquipment               tcap.LocalCode = 7  // unknownEquipment
	ErrorCodeRoamingNotAllowed              tcap.LocalCode = 8  // roamingNotAllowed
	ErrorCodeIllegalSubscriber              tcap.LocalCode = 9  // illegalSubscriber
	ErrorCodeBearerServiceNotProvisioned    tcap.LocalCode = 10 // bearerServiceNotProvisioned
	ErrorCodeTeleserviceNotProvisioned      tcap.LocalCode = 11 // teleserviceNotProvisioned
	ErrorCodeIllegalEquipment               tcap.LocalCode = 12 // illegalEquipment
	ErrorCodeCallBarred                     tcap.LocalCode = 13 // callBarred
	ErrorCodeForwardingViolation            tcap.LocalCode = 14 // forwardingViolation
	ErrorCodeCUGReject                      tcap.LocalCode = 15 // cug-Reject
	ErrorCodeIllegalSSOperation             tcap.LocalCode = 16 // illegalSS-Operation
	ErrorCodeSSErrorStatus                  tcap.LocalCode = 17 // ss-ErrorStatus
	ErrorCodeSSNotAvailable                 tcap.LocalCode = 18 // ss-NotAvailable
	ErrorCodeSSSubscriptionViolation        tcap.LocalCode = 19 // ss-SubscriptionViolation
	ErrorCodeSSIncompatibility              tcap.LocalCode = 20 // ss-Incompatibility
	ErrorCodeFacilityNotSupported           tcap.LocalCode = 21 // facilityNotSupported
	ErrorCodeOngoingGroupCall               tcap.LocalCode = 22 // ongoingGroupCall
	ErrorCodeNoHandoverNumberAvailable      tcap.LocalCode = 25 // noHandoverNumberAvailable
	ErrorCodeSubsequentHandoverFailure      tcap.LocalCode = 26 // subsequentHandoverFailure
	ErrorCodeAbsentSubscriber               tcap.LocalCode = 27 // absentSubscriber
	ErrorCodeIncompatibleTerminal           tcap.LocalCode = 28 // incompatibleTerminal
	ErrorCodeShortTermDenial                tcap.LocalCode = 29 // shortTermDenial
	ErrorCodeLongTermDenial                 tcap.LocalCode = 30 // longTermDenial
	ErrorCodeSubscriberBusyForMTSMS         tcap.LocalCode = 31 // subscriberBusyForMT-SMS
	ErrorCodeSMDeliveryFailure              tcap.LocalCode = 32 // sm-DeliveryFailure
	ErrorCodeMessageWaitingListFull         tcap.LocalCode = 33 // messageWaitingListFull
	ErrorCodeSystemFailure                  tcap.LocalCode = 34 // systemFailure
	ErrorCodeDataMissing                    tcap.LocalCode = 35 // dataMissing
	ErrorCodeUnexpectedDataValue            tcap.LocalCode = 36 // unexpectedDataValue
	ErrorCodePWRegistrationFailure          tcap.LocalCode = 37 // pw-RegistrationFailure
	ErrorCodeNegativePWCheck                tcap.LocalCode = 38 // negativePW-Check
	ErrorCodeNoRoamingNumberAvailable       tcap.LocalCode = 39 // noRoamingNumberAvailable
	ErrorCodeTracingBufferFull              tcap.LocalCode = 40 // tracingBufferFull
	ErrorCodeTargetCellOutsideGroupCallArea tcap.LocalCode = 42 // targetCellOutsideGroupCallArea
	ErrorCodeNumberOfPWAttemptsViolation    tcap.LocalCode = 43 // numberOfPW-AttemptsViolation
	ErrorCodeNumberChanged                  tcap.LocalCode = 44 // numberChanged
	ErrorCodeBusySubscriber                 tcap.LocalCode = 45 // busySubscriber
	ErrorCodeNoSubscriberReply              tcap.LocalCode = 46 // noSubscriberReply
	ErrorCodeForwardingFailed               tcap.LocalCode = 47 // forwardingFailed
	ErrorCodeORNotAllowed                   tcap.LocalCode = 48 // or-NotAllowed
	ErrorCodeATINotAllowed                  tcap.LocalCode = 49 // ati-NotAllowed
	ErrorCodeNoGroupCallNumberAvailable     tcap.LocalCode = 50 // noGroupCallNumberAvailable
	ErrorCodeResourceLimitation             tcap.LocalCode = 51 // resourceLimitation
	ErrorCodeUnauthorizedRequestingNetwork  tcap.LocalCode = 52 // unauthorizedRequestingNetwork
	ErrorCodeUnauthorizedLCSClient          tcap.LocalCode = 53 // unauthorizedLCSClient
	ErrorCodePositionMethodFailure          tcap.LocalCode = 54 // positionMethodFailure
	ErrorCodeUnknownOrUnreachableLCSClient  tcap.LocalCode = 58 // unknownOrUnreachableLCSClient
	ErrorCodeMMEventNotSupported            tcap.LocalCode = 59 // mm-EventNotSupported
	ErrorCodeATSINotAllowed                 tcap.LocalCode = 60 // atsi-NotAllowed
	ErrorCodeATMNotAllowed                  tcap.LocalCode = 61 // atm-NotAllowed
	ErrorCodeInformationNotAvailable        tcap.LocalCode = 62 // informationNotAvailable
	ErrorCodeUnknownAlphabet                tcap.LocalCode = 71 // unknownAlphabet
	ErrorCodeUSSDBusy                       tcap.LocalCode = 72 // ussd-Busy
)

// Error codes reserved for errors of previous versions of the protocol:
// 3GPP TS 29.002 V19.1.0 clause 17.5, module MAP-Protocol.
const (
	ErrorCodeUnknownBaseStation       tcap.LocalCode = 2  // unknownBaseStation
	ErrorCodeInvalidTargetBaseStation tcap.LocalCode = 23 // invalidTargetBaseStation
	ErrorCodeNoRadioResourceAvailable tcap.LocalCode = 24 // noRadioResourceAvailable
)
