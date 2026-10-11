package gsmmap

import "github.com/gomaja/go-asn1-tcap"

// Operation codes (local values of the operation code in an Invoke) currently
// defined by 3GPP TS 29.002 V19.1.0 clause 17.6, modules MAP-MobileServiceOperations
// (17.6.1), MAP-OperationAndMaintenanceOperations (17.6.2),
// MAP-CallHandlingOperations (17.6.3), MAP-SupplementaryServiceOperations
// (17.6.4), MAP-ShortMessageServiceOperations (17.6.5),
// MAP-Group-Call-Operations (17.6.7) and MAP-LocationServiceOperations (17.6.8).
const (
	OpCodeUpdateLocation                   tcap.LocalCode = 2  // updateLocation
	OpCodeCancelLocation                   tcap.LocalCode = 3  // cancelLocation
	OpCodeProvideRoamingNumber             tcap.LocalCode = 4  // provideRoamingNumber
	OpCodeNoteSubscriberDataModified       tcap.LocalCode = 5  // noteSubscriberDataModified
	OpCodeResumeCallHandling               tcap.LocalCode = 6  // resumeCallHandling
	OpCodeInsertSubscriberData             tcap.LocalCode = 7  // insertSubscriberData
	OpCodeDeleteSubscriberData             tcap.LocalCode = 8  // deleteSubscriberData
	OpCodeRegisterSS                       tcap.LocalCode = 10 // registerSS
	OpCodeEraseSS                          tcap.LocalCode = 11 // eraseSS
	OpCodeActivateSS                       tcap.LocalCode = 12 // activateSS
	OpCodeDeactivateSS                     tcap.LocalCode = 13 // deactivateSS
	OpCodeInterrogateSS                    tcap.LocalCode = 14 // interrogateSS
	OpCodeAuthenticationFailureReport      tcap.LocalCode = 15 // authenticationFailureReport
	OpCodeRegisterPassword                 tcap.LocalCode = 17 // registerPassword
	OpCodeGetPassword                      tcap.LocalCode = 18 // getPassword
	OpCodeReleaseResources                 tcap.LocalCode = 20 // releaseResources
	OpCodeMTForwardSMVGCS                  tcap.LocalCode = 21 // mt-ForwardSM-VGCS
	OpCodeSendRoutingInfo                  tcap.LocalCode = 22 // sendRoutingInfo
	OpCodeUpdateGprsLocation               tcap.LocalCode = 23 // updateGprsLocation
	OpCodeSendRoutingInfoForGprs           tcap.LocalCode = 24 // sendRoutingInfoForGprs
	OpCodeFailureReport                    tcap.LocalCode = 25 // failureReport
	OpCodeNoteMsPresentForGprs             tcap.LocalCode = 26 // noteMsPresentForGprs
	OpCodeSendEndSignal                    tcap.LocalCode = 29 // sendEndSignal
	OpCodeProcessAccessSignalling          tcap.LocalCode = 33 // processAccessSignalling
	OpCodeForwardAccessSignalling          tcap.LocalCode = 34 // forwardAccessSignalling
	OpCodeCancelVcsgLocation               tcap.LocalCode = 36 // cancelVcsgLocation
	OpCodeReset                            tcap.LocalCode = 37 // reset
	OpCodeForwardCheckSSIndication         tcap.LocalCode = 38 // forwardCheckSS-Indication
	OpCodePrepareGroupCall                 tcap.LocalCode = 39 // prepareGroupCall
	OpCodeSendGroupCallEndSignal           tcap.LocalCode = 40 // sendGroupCallEndSignal
	OpCodeProcessGroupCallSignalling       tcap.LocalCode = 41 // processGroupCallSignalling
	OpCodeForwardGroupCallSignalling       tcap.LocalCode = 42 // forwardGroupCallSignalling
	OpCodeCheckIMEI                        tcap.LocalCode = 43 // checkIMEI
	OpCodeMTForwardSM                      tcap.LocalCode = 44 // mt-ForwardSM
	OpCodeSendRoutingInfoForSM             tcap.LocalCode = 45 // sendRoutingInfoForSM
	OpCodeMOForwardSM                      tcap.LocalCode = 46 // mo-ForwardSM
	OpCodeReportSMDeliveryStatus           tcap.LocalCode = 47 // reportSM-DeliveryStatus
	OpCodeActivateTraceMode                tcap.LocalCode = 50 // activateTraceMode
	OpCodeDeactivateTraceMode              tcap.LocalCode = 51 // deactivateTraceMode
	OpCodeUpdateVcsgLocation               tcap.LocalCode = 53 // updateVcsgLocation
	OpCodeSendIdentification               tcap.LocalCode = 55 // sendIdentification
	OpCodeSendAuthenticationInfo           tcap.LocalCode = 56 // sendAuthenticationInfo
	OpCodeRestoreData                      tcap.LocalCode = 57 // restoreData
	OpCodeSendIMSI                         tcap.LocalCode = 58 // sendIMSI
	OpCodeProcessUnstructuredSSRequest     tcap.LocalCode = 59 // processUnstructuredSS-Request
	OpCodeUnstructuredSSRequest            tcap.LocalCode = 60 // unstructuredSS-Request
	OpCodeUnstructuredSSNotify             tcap.LocalCode = 61 // unstructuredSS-Notify
	OpCodeAnyTimeSubscriptionInterrogation tcap.LocalCode = 62 // anyTimeSubscriptionInterrogation
	OpCodeInformServiceCentre              tcap.LocalCode = 63 // informServiceCentre
	OpCodeAlertServiceCentre               tcap.LocalCode = 64 // alertServiceCentre
	OpCodeAnyTimeModification              tcap.LocalCode = 65 // anyTimeModification
	OpCodeReadyForSM                       tcap.LocalCode = 66 // readyForSM
	OpCodePurgeMS                          tcap.LocalCode = 67 // purgeMS
	OpCodePrepareHandover                  tcap.LocalCode = 68 // prepareHandover
	OpCodePrepareSubsequentHandover        tcap.LocalCode = 69 // prepareSubsequentHandover
	OpCodeProvideSubscriberInfo            tcap.LocalCode = 70 // provideSubscriberInfo
	OpCodeAnyTimeInterrogation             tcap.LocalCode = 71 // anyTimeInterrogation
	OpCodeSSInvocationNotification         tcap.LocalCode = 72 // ss-InvocationNotification
	OpCodeSetReportingState                tcap.LocalCode = 73 // setReportingState
	OpCodeStatusReport                     tcap.LocalCode = 74 // statusReport
	OpCodeRemoteUserFree                   tcap.LocalCode = 75 // remoteUserFree
	OpCodeRegisterCCEntry                  tcap.LocalCode = 76 // registerCC-Entry
	OpCodeEraseCCEntry                     tcap.LocalCode = 77 // eraseCC-Entry
	OpCodeProvideSubscriberLocation        tcap.LocalCode = 83 // provideSubscriberLocation
	OpCodeSendGroupCallInfo                tcap.LocalCode = 84 // sendGroupCallInfo
	OpCodeSendRoutingInfoForLCS            tcap.LocalCode = 85 // sendRoutingInfoForLCS
	OpCodeSubscriberLocationReport         tcap.LocalCode = 86 // subscriberLocationReport
	OpCodeISTAlert                         tcap.LocalCode = 87 // ist-Alert
	OpCodeISTCommand                       tcap.LocalCode = 88 // ist-Command
	OpCodeNoteMMEvent                      tcap.LocalCode = 89 // noteMM-Event
)

// Operation codes reserved for operations of previous versions of the protocol:
// 3GPP TS 29.002 V19.1.0 clause 17.5, module MAP-Protocol.
const (
	OpCodeSendParameters                  tcap.LocalCode = 9  // sendParameters
	OpCodeProcessUnstructuredSSData       tcap.LocalCode = 19 // processUnstructuredSS-Data
	OpCodePerformHandover                 tcap.LocalCode = 28 // performHandover
	OpCodePerformSubsequentHandover       tcap.LocalCode = 30 // performSubsequentHandover
	OpCodeProvideSIWFSNumber              tcap.LocalCode = 31 // provideSIWFSNumber
	OpCodeSIWFSSignallingModify           tcap.LocalCode = 32 // siwfs-SignallingModify
	OpCodeNoteInternalHandover            tcap.LocalCode = 35 // noteInternalHandover
	OpCodeNoteSubscriberPresent           tcap.LocalCode = 48 // noteSubscriberPresent
	OpCodeAlertServiceCentreWithoutResult tcap.LocalCode = 49 // alertServiceCentreWithoutResult
	OpCodeTraceSubscriberActivity         tcap.LocalCode = 52 // traceSubscriberActivity
	OpCodeBeginSubscriberActivity         tcap.LocalCode = 54 // beginSubscriberActivity
)
