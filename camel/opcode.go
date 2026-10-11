package camel

import "github.com/gomaja/go-asn1-tcap"

// Operation codes (local values of the operation code in an Invoke) of 3GPP TS
// 29.078 V19.0.0 clause 5.3, module CAP-operationcodes.
const (
	OpCodeInitialDP                       tcap.LocalCode = 0  // opcode-initialDP
	OpCodeAssistRequestInstructions       tcap.LocalCode = 16 // opcode-assistRequestInstructions
	OpCodeEstablishTemporaryConnection    tcap.LocalCode = 17 // opcode-establishTemporaryConnection
	OpCodeDisconnectForwardConnection     tcap.LocalCode = 18 // opcode-disconnectForwardConnection
	OpCodeConnectToResource               tcap.LocalCode = 19 // opcode-connectToResource
	OpCodeConnect                         tcap.LocalCode = 20 // opcode-connect
	OpCodeReleaseCall                     tcap.LocalCode = 22 // opcode-releaseCall
	OpCodeRequestReportBCSMEvent          tcap.LocalCode = 23 // opcode-requestReportBCSMEvent
	OpCodeEventReportBCSM                 tcap.LocalCode = 24 // opcode-eventReportBCSM
	OpCodeCollectInformation              tcap.LocalCode = 27 // opcode-collectInformation
	OpCodeContinue                        tcap.LocalCode = 31 // opcode-continue
	OpCodeInitiateCallAttempt             tcap.LocalCode = 32 // opcode-initiateCallAttempt
	OpCodeResetTimer                      tcap.LocalCode = 33 // opcode-resetTimer
	OpCodeFurnishChargingInformation      tcap.LocalCode = 34 // opcode-furnishChargingInformation
	OpCodeApplyCharging                   tcap.LocalCode = 35 // opcode-applyCharging
	OpCodeApplyChargingReport             tcap.LocalCode = 36 // opcode-applyChargingReport
	OpCodeCallGap                         tcap.LocalCode = 41 // opcode-callGap
	OpCodeCallInformationReport           tcap.LocalCode = 44 // opcode-callInformationReport
	OpCodeCallInformationRequest          tcap.LocalCode = 45 // opcode-callInformationRequest
	OpCodeSendChargingInformation         tcap.LocalCode = 46 // opcode-sendChargingInformation
	OpCodePlayAnnouncement                tcap.LocalCode = 47 // opcode-playAnnouncement
	OpCodePromptAndCollectUserInformation tcap.LocalCode = 48 // opcode-promptAndCollectUserInformation
	OpCodeSpecializedResourceReport       tcap.LocalCode = 49 // opcode-specializedResourceReport
	OpCodeCancel                          tcap.LocalCode = 53 // opcode-cancel
	OpCodeActivityTest                    tcap.LocalCode = 55 // opcode-activityTest
	OpCodeInitialDPSMS                    tcap.LocalCode = 60 // opcode-initialDPSMS
	OpCodeFurnishChargingInformationSMS   tcap.LocalCode = 61 // opcode-furnishChargingInformationSMS
	OpCodeConnectSMS                      tcap.LocalCode = 62 // opcode-connectSMS
	OpCodeRequestReportSMSEvent           tcap.LocalCode = 63 // opcode-requestReportSMSEvent
	OpCodeEventReportSMS                  tcap.LocalCode = 64 // opcode-eventReportSMS
	OpCodeContinueSMS                     tcap.LocalCode = 65 // opcode-continueSMS
	OpCodeReleaseSMS                      tcap.LocalCode = 66 // opcode-releaseSMS
	OpCodeResetTimerSMS                   tcap.LocalCode = 67 // opcode-resetTimerSMS
	OpCodeActivityTestGPRS                tcap.LocalCode = 70 // opcode-activityTestGPRS
	OpCodeApplyChargingGPRS               tcap.LocalCode = 71 // opcode-applyChargingGPRS
	OpCodeApplyChargingReportGPRS         tcap.LocalCode = 72 // opcode-applyChargingReportGPRS
	OpCodeCancelGPRS                      tcap.LocalCode = 73 // opcode-cancelGPRS
	OpCodeConnectGPRS                     tcap.LocalCode = 74 // opcode-connectGPRS
	OpCodeContinueGPRS                    tcap.LocalCode = 75 // opcode-continueGPRS
	OpCodeEntityReleasedGPRS              tcap.LocalCode = 76 // opcode-entityReleasedGPRS
	OpCodeFurnishChargingInformationGPRS  tcap.LocalCode = 77 // opcode-furnishChargingInformationGPRS
	OpCodeInitialDPGPRS                   tcap.LocalCode = 78 // opcode-initialDPGPRS
	OpCodeReleaseGPRS                     tcap.LocalCode = 79 // opcode-releaseGPRS
	OpCodeEventReportGPRS                 tcap.LocalCode = 80 // opcode-eventReportGPRS
	OpCodeRequestReportGPRSEvent          tcap.LocalCode = 81 // opcode-requestReportGPRSEvent
	OpCodeResetTimerGPRS                  tcap.LocalCode = 82 // opcode-resetTimerGPRS
	OpCodeSendChargingInformationGPRS     tcap.LocalCode = 83 // opcode-sendChargingInformationGPRS
	OpCodeDFCWithArgument                 tcap.LocalCode = 86 // opcode-dFCWithArgument
	OpCodeContinueWithArgument            tcap.LocalCode = 88 // opcode-continueWithArgument
	OpCodeDisconnectLeg                   tcap.LocalCode = 90 // opcode-disconnectLeg
	OpCodeMoveLeg                         tcap.LocalCode = 93 // opcode-moveLeg
	OpCodeSplitLeg                        tcap.LocalCode = 95 // opcode-splitLeg
	OpCodeEntityReleased                  tcap.LocalCode = 96 // opcode-entityReleased
	OpCodePlayTone                        tcap.LocalCode = 97 // opcode-playTone
)
