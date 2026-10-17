package gsmmap_test

// Code generated for the oracle comparison tables; the entries pair each
// constant with the go-asn1 constant of the same value.

import (
	"github.com/gomaja/go-asn1-tcap"
	"github.com/gomaja/go-asn1-tcap/gsmmap"
	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
)

type contextCase struct {
	name  string
	value tcap.OID
	fn    func() runtime.ObjectIdentifier
}

type codeCase struct {
	name   string
	value  tcap.LocalCode
	oracle int64
}

// currentContexts pairs the 44 current contexts with the go-asn1 functions of
// the same name.
var currentContexts = []contextCase{
	{"NetworkLocUpContextV3", gsmmap.NetworkLocUpContextV3, gsm_map.NetworkLocUpContextV3},
	{"LocationCancellationContextV3", gsmmap.LocationCancellationContextV3, gsm_map.LocationCancellationContextV3},
	{"RoamingNumberEnquiryContextV3", gsmmap.RoamingNumberEnquiryContextV3, gsm_map.RoamingNumberEnquiryContextV3},
	{"AuthenticationFailureReportContextV3", gsmmap.AuthenticationFailureReportContextV3, gsm_map.AuthenticationFailureReportContextV3},
	{"LocationInfoRetrievalContextV3", gsmmap.LocationInfoRetrievalContextV3, gsm_map.LocationInfoRetrievalContextV3},
	{"ResetContextV3", gsmmap.ResetContextV3, gsm_map.ResetContextV3},
	{"HandoverControlContextV3", gsmmap.HandoverControlContextV3, gsm_map.HandoverControlContextV3},
	{"EquipmentMngtContextV3", gsmmap.EquipmentMngtContextV3, gsm_map.EquipmentMngtContextV3},
	{"InfoRetrievalContextV3", gsmmap.InfoRetrievalContextV3, gsm_map.InfoRetrievalContextV3},
	{"InterVlrInfoRetrievalContextV3", gsmmap.InterVlrInfoRetrievalContextV3, gsm_map.InterVlrInfoRetrievalContextV3},
	{"SubscriberDataMngtContextV3", gsmmap.SubscriberDataMngtContextV3, gsm_map.SubscriberDataMngtContextV3},
	{"TracingContextV3", gsmmap.TracingContextV3, gsm_map.TracingContextV3},
	{"NetworkFunctionalSsContextV2", gsmmap.NetworkFunctionalSsContextV2, gsm_map.NetworkFunctionalSsContextV2},
	{"NetworkUnstructuredSsContextV2", gsmmap.NetworkUnstructuredSsContextV2, gsm_map.NetworkUnstructuredSsContextV2},
	{"ShortMsgGatewayContextV3", gsmmap.ShortMsgGatewayContextV3, gsm_map.ShortMsgGatewayContextV3},
	{"ShortMsgMORelayContextV3", gsmmap.ShortMsgMORelayContextV3, gsm_map.ShortMsgMORelayContextV3},
	{"ShortMsgAlertContextV2", gsmmap.ShortMsgAlertContextV2, gsm_map.ShortMsgAlertContextV2},
	{"MwdMngtContextV3", gsmmap.MwdMngtContextV3, gsm_map.MwdMngtContextV3},
	{"ShortMsgMTRelayContextV3", gsmmap.ShortMsgMTRelayContextV3, gsm_map.ShortMsgMTRelayContextV3},
	{"ShortMsgMTRelayVGCSContextV3", gsmmap.ShortMsgMTRelayVGCSContextV3, gsm_map.ShortMsgMTRelayVGCSContextV3},
	{"ImsiRetrievalContextV2", gsmmap.ImsiRetrievalContextV2, gsm_map.ImsiRetrievalContextV2},
	{"MsPurgingContextV3", gsmmap.MsPurgingContextV3, gsm_map.MsPurgingContextV3},
	{"SubscriberInfoEnquiryContextV3", gsmmap.SubscriberInfoEnquiryContextV3, gsm_map.SubscriberInfoEnquiryContextV3},
	{"AnyTimeInfoEnquiryContextV3", gsmmap.AnyTimeInfoEnquiryContextV3, gsm_map.AnyTimeInfoEnquiryContextV3},
	{"CallControlTransferContextV4", gsmmap.CallControlTransferContextV4, gsm_map.CallControlTransferContextV4},
	{"SSInvocationNotificationContextV3", gsmmap.SSInvocationNotificationContextV3, gsm_map.SsInvocationNotificationContextV3},
	{"GroupCallControlContextV3", gsmmap.GroupCallControlContextV3, gsm_map.GroupCallControlContextV3},
	{"GroupCallInfoRetrievalContextV3", gsmmap.GroupCallInfoRetrievalContextV3, gsm_map.GroupCallInfoRetrievalContextV3},
	{"GprsLocationUpdateContextV3", gsmmap.GprsLocationUpdateContextV3, gsm_map.GprsLocationUpdateContextV3},
	{"GprsLocationInfoRetrievalContextV4", gsmmap.GprsLocationInfoRetrievalContextV4, gsm_map.GprsLocationInfoRetrievalContextV4},
	{"FailureReportContextV3", gsmmap.FailureReportContextV3, gsm_map.FailureReportContextV3},
	{"GprsNotifyContextV3", gsmmap.GprsNotifyContextV3, gsm_map.GprsNotifyContextV3},
	{"ReportingContextV3", gsmmap.ReportingContextV3, gsm_map.ReportingContextV3},
	{"CallCompletionContextV3", gsmmap.CallCompletionContextV3, gsm_map.CallCompletionContextV3},
	{"IstAlertingContextV3", gsmmap.IstAlertingContextV3, gsm_map.IstAlertingContextV3},
	{"ServiceTerminationContextV3", gsmmap.ServiceTerminationContextV3, gsm_map.ServiceTerminationContextV3},
	{"LocationSvcGatewayContextV3", gsmmap.LocationSvcGatewayContextV3, gsm_map.LocationSvcGatewayContextV3},
	{"LocationSvcEnquiryContextV3", gsmmap.LocationSvcEnquiryContextV3, gsm_map.LocationSvcEnquiryContextV3},
	{"MMEventReportingContextV3", gsmmap.MMEventReportingContextV3, gsm_map.MmEventReportingContextV3},
	{"AnyTimeInfoHandlingContextV3", gsmmap.AnyTimeInfoHandlingContextV3, gsm_map.AnyTimeInfoHandlingContextV3},
	{"SubscriberDataModificationNotificationContextV3", gsmmap.SubscriberDataModificationNotificationContextV3, gsm_map.SubscriberDataModificationNotificationContextV3},
	{"ResourceManagementContextV3", gsmmap.ResourceManagementContextV3, gsm_map.ResourceManagementContextV3},
	{"VcsgLocationUpdateContextV3", gsmmap.VcsgLocationUpdateContextV3, gsm_map.VcsgLocationUpdateContextV3},
	{"VcsgLocationCancellationContextV3", gsmmap.VcsgLocationCancellationContextV3, gsm_map.VcsgLocationCancellationContextV3},
}

// reservedContexts lists the 33 reserved contexts, which go-asn1 does not
// generate, with their values read from the list of reserved object
// identifiers in 3GPP TS 29.002 V19.1.0 clause 17.3.3.
var reservedContexts = []struct {
	name  string
	value tcap.OID
	want  tcap.OID
}{
	{"NetworkLocUpContextV1", gsmmap.NetworkLocUpContextV1, "0.4.0.0.1.0.1.1"},
	{"NetworkLocUpContextV2", gsmmap.NetworkLocUpContextV2, "0.4.0.0.1.0.1.2"},
	{"LocationCancellationContextV1", gsmmap.LocationCancellationContextV1, "0.4.0.0.1.0.2.1"},
	{"LocationCancellationContextV2", gsmmap.LocationCancellationContextV2, "0.4.0.0.1.0.2.2"},
	{"RoamingNumberEnquiryContextV1", gsmmap.RoamingNumberEnquiryContextV1, "0.4.0.0.1.0.3.1"},
	{"RoamingNumberEnquiryContextV2", gsmmap.RoamingNumberEnquiryContextV2, "0.4.0.0.1.0.3.2"},
	{"LocationInfoRetrievalContextV1", gsmmap.LocationInfoRetrievalContextV1, "0.4.0.0.1.0.5.1"},
	{"LocationInfoRetrievalContextV2", gsmmap.LocationInfoRetrievalContextV2, "0.4.0.0.1.0.5.2"},
	{"ResetContextV1", gsmmap.ResetContextV1, "0.4.0.0.1.0.10.1"},
	{"ResetContextV2", gsmmap.ResetContextV2, "0.4.0.0.1.0.10.2"},
	{"HandoverControlContextV1", gsmmap.HandoverControlContextV1, "0.4.0.0.1.0.11.1"},
	{"HandoverControlContextV2", gsmmap.HandoverControlContextV2, "0.4.0.0.1.0.11.2"},
	{"SIWFSAllocationContextV3", gsmmap.SIWFSAllocationContextV3, "0.4.0.0.1.0.12.3"},
	{"EquipmentMngtContextV1", gsmmap.EquipmentMngtContextV1, "0.4.0.0.1.0.13.1"},
	{"EquipmentMngtContextV2", gsmmap.EquipmentMngtContextV2, "0.4.0.0.1.0.13.2"},
	{"InfoRetrievalContextV1", gsmmap.InfoRetrievalContextV1, "0.4.0.0.1.0.14.1"},
	{"InfoRetrievalContextV2", gsmmap.InfoRetrievalContextV2, "0.4.0.0.1.0.14.2"},
	{"InterVlrInfoRetrievalContextV2", gsmmap.InterVlrInfoRetrievalContextV2, "0.4.0.0.1.0.15.2"},
	{"SubscriberDataMngtContextV1", gsmmap.SubscriberDataMngtContextV1, "0.4.0.0.1.0.16.1"},
	{"SubscriberDataMngtContextV2", gsmmap.SubscriberDataMngtContextV2, "0.4.0.0.1.0.16.2"},
	{"TracingContextV1", gsmmap.TracingContextV1, "0.4.0.0.1.0.17.1"},
	{"TracingContextV2", gsmmap.TracingContextV2, "0.4.0.0.1.0.17.2"},
	{"NetworkFunctionalSsContextV1", gsmmap.NetworkFunctionalSsContextV1, "0.4.0.0.1.0.18.1"},
	{"ShortMsgGatewayContextV1", gsmmap.ShortMsgGatewayContextV1, "0.4.0.0.1.0.20.1"},
	{"ShortMsgGatewayContextV2", gsmmap.ShortMsgGatewayContextV2, "0.4.0.0.1.0.20.2"},
	{"ShortMsgRelayContextV1", gsmmap.ShortMsgRelayContextV1, "0.4.0.0.1.0.21.1"},
	{"ShortMsgAlertContextV1", gsmmap.ShortMsgAlertContextV1, "0.4.0.0.1.0.23.1"},
	{"MwdMngtContextV1", gsmmap.MwdMngtContextV1, "0.4.0.0.1.0.24.1"},
	{"MwdMngtContextV2", gsmmap.MwdMngtContextV2, "0.4.0.0.1.0.24.2"},
	{"ShortMsgMTRelayContextV2", gsmmap.ShortMsgMTRelayContextV2, "0.4.0.0.1.0.25.2"},
	{"MsPurgingContextV2", gsmmap.MsPurgingContextV2, "0.4.0.0.1.0.27.2"},
	{"CallControlTransferContextV3", gsmmap.CallControlTransferContextV3, "0.4.0.0.1.0.6.3"},
	{"GprsLocationInfoRetrievalContextV3", gsmmap.GprsLocationInfoRetrievalContextV3, "0.4.0.0.1.0.33.3"},
}

// operationCodes uses the current go-asn1 information-object catalogue.
// Literal historical reservations are from TS 29.002 V19.1.0 clause 17.5;
// checked against the d77484b generated MAP-Protocol assignments.
var operationCodes = []codeCase{
	{"OpCodeUpdateLocation", gsmmap.OpCodeUpdateLocation, int64(gsm_map.UpdateLocation)},
	{"OpCodeCancelLocation", gsmmap.OpCodeCancelLocation, int64(gsm_map.CancelLocation)},
	{"OpCodeProvideRoamingNumber", gsmmap.OpCodeProvideRoamingNumber, int64(gsm_map.ProvideRoamingNumber)},
	{"OpCodeNoteSubscriberDataModified", gsmmap.OpCodeNoteSubscriberDataModified, int64(gsm_map.NoteSubscriberDataModified)},
	{"OpCodeResumeCallHandling", gsmmap.OpCodeResumeCallHandling, int64(gsm_map.ResumeCallHandling)},
	{"OpCodeInsertSubscriberData", gsmmap.OpCodeInsertSubscriberData, int64(gsm_map.InsertSubscriberData)},
	{"OpCodeDeleteSubscriberData", gsmmap.OpCodeDeleteSubscriberData, int64(gsm_map.DeleteSubscriberData)},
	{"OpCodeRegisterSS", gsmmap.OpCodeRegisterSS, int64(gsm_map.RegisterSS)},
	{"OpCodeEraseSS", gsmmap.OpCodeEraseSS, int64(gsm_map.EraseSS)},
	{"OpCodeActivateSS", gsmmap.OpCodeActivateSS, int64(gsm_map.ActivateSS)},
	{"OpCodeDeactivateSS", gsmmap.OpCodeDeactivateSS, int64(gsm_map.DeactivateSS)},
	{"OpCodeInterrogateSS", gsmmap.OpCodeInterrogateSS, int64(gsm_map.InterrogateSS)},
	{"OpCodeAuthenticationFailureReport", gsmmap.OpCodeAuthenticationFailureReport, int64(gsm_map.AuthenticationFailureReport)},
	{"OpCodeRegisterPassword", gsmmap.OpCodeRegisterPassword, int64(gsm_map.RegisterPassword)},
	{"OpCodeGetPassword", gsmmap.OpCodeGetPassword, int64(gsm_map.GetPassword)},
	{"OpCodeReleaseResources", gsmmap.OpCodeReleaseResources, int64(gsm_map.ReleaseResources)},
	{"OpCodeMTForwardSMVGCS", gsmmap.OpCodeMTForwardSMVGCS, int64(gsm_map.MtForwardSMVGCS)},
	{"OpCodeSendRoutingInfo", gsmmap.OpCodeSendRoutingInfo, int64(gsm_map.SendRoutingInfo)},
	{"OpCodeUpdateGprsLocation", gsmmap.OpCodeUpdateGprsLocation, int64(gsm_map.UpdateGprsLocation)},
	{"OpCodeSendRoutingInfoForGprs", gsmmap.OpCodeSendRoutingInfoForGprs, int64(gsm_map.SendRoutingInfoForGprs)},
	{"OpCodeFailureReport", gsmmap.OpCodeFailureReport, int64(gsm_map.FailureReport)},
	{"OpCodeNoteMsPresentForGprs", gsmmap.OpCodeNoteMsPresentForGprs, int64(gsm_map.NoteMsPresentForGprs)},
	{"OpCodeSendEndSignal", gsmmap.OpCodeSendEndSignal, int64(gsm_map.SendEndSignal)},
	{"OpCodeProcessAccessSignalling", gsmmap.OpCodeProcessAccessSignalling, int64(gsm_map.ProcessAccessSignalling)},
	{"OpCodeForwardAccessSignalling", gsmmap.OpCodeForwardAccessSignalling, int64(gsm_map.ForwardAccessSignalling)},
	{"OpCodeCancelVcsgLocation", gsmmap.OpCodeCancelVcsgLocation, int64(gsm_map.CancelVcsgLocation)},
	{"OpCodeReset", gsmmap.OpCodeReset, int64(gsm_map.Reset)},
	{"OpCodeForwardCheckSSIndication", gsmmap.OpCodeForwardCheckSSIndication, int64(gsm_map.ForwardCheckSSIndication)},
	{"OpCodePrepareGroupCall", gsmmap.OpCodePrepareGroupCall, int64(gsm_map.PrepareGroupCall)},
	{"OpCodeSendGroupCallEndSignal", gsmmap.OpCodeSendGroupCallEndSignal, int64(gsm_map.SendGroupCallEndSignal)},
	{"OpCodeProcessGroupCallSignalling", gsmmap.OpCodeProcessGroupCallSignalling, int64(gsm_map.ProcessGroupCallSignalling)},
	{"OpCodeForwardGroupCallSignalling", gsmmap.OpCodeForwardGroupCallSignalling, int64(gsm_map.ForwardGroupCallSignalling)},
	{"OpCodeCheckIMEI", gsmmap.OpCodeCheckIMEI, int64(gsm_map.CheckIMEI)},
	{"OpCodeMTForwardSM", gsmmap.OpCodeMTForwardSM, int64(gsm_map.MtForwardSM)},
	{"OpCodeSendRoutingInfoForSM", gsmmap.OpCodeSendRoutingInfoForSM, int64(gsm_map.SendRoutingInfoForSM)},
	{"OpCodeMOForwardSM", gsmmap.OpCodeMOForwardSM, int64(gsm_map.MoForwardSM)},
	{"OpCodeReportSMDeliveryStatus", gsmmap.OpCodeReportSMDeliveryStatus, int64(gsm_map.ReportSMDeliveryStatus)},
	{"OpCodeActivateTraceMode", gsmmap.OpCodeActivateTraceMode, int64(gsm_map.ActivateTraceMode)},
	{"OpCodeDeactivateTraceMode", gsmmap.OpCodeDeactivateTraceMode, int64(gsm_map.DeactivateTraceMode)},
	{"OpCodeUpdateVcsgLocation", gsmmap.OpCodeUpdateVcsgLocation, int64(gsm_map.UpdateVcsgLocation)},
	{"OpCodeSendIdentification", gsmmap.OpCodeSendIdentification, int64(gsm_map.SendIdentification)},
	{"OpCodeSendAuthenticationInfo", gsmmap.OpCodeSendAuthenticationInfo, int64(gsm_map.SendAuthenticationInfo)},
	{"OpCodeRestoreData", gsmmap.OpCodeRestoreData, int64(gsm_map.RestoreData)},
	{"OpCodeSendIMSI", gsmmap.OpCodeSendIMSI, int64(gsm_map.SendIMSI)},
	{"OpCodeProcessUnstructuredSSRequest", gsmmap.OpCodeProcessUnstructuredSSRequest, int64(gsm_map.ProcessUnstructuredSSRequest)},
	{"OpCodeUnstructuredSSRequest", gsmmap.OpCodeUnstructuredSSRequest, int64(gsm_map.UnstructuredSSRequest)},
	{"OpCodeUnstructuredSSNotify", gsmmap.OpCodeUnstructuredSSNotify, int64(gsm_map.UnstructuredSSNotify)},
	{"OpCodeAnyTimeSubscriptionInterrogation", gsmmap.OpCodeAnyTimeSubscriptionInterrogation, int64(gsm_map.AnyTimeSubscriptionInterrogation)},
	{"OpCodeInformServiceCentre", gsmmap.OpCodeInformServiceCentre, int64(gsm_map.InformServiceCentre)},
	{"OpCodeAlertServiceCentre", gsmmap.OpCodeAlertServiceCentre, int64(gsm_map.AlertServiceCentre)},
	{"OpCodeAnyTimeModification", gsmmap.OpCodeAnyTimeModification, int64(gsm_map.AnyTimeModification)},
	{"OpCodeReadyForSM", gsmmap.OpCodeReadyForSM, int64(gsm_map.ReadyForSM)},
	{"OpCodePurgeMS", gsmmap.OpCodePurgeMS, int64(gsm_map.PurgeMS)},
	{"OpCodePrepareHandover", gsmmap.OpCodePrepareHandover, int64(gsm_map.PrepareHandover)},
	{"OpCodePrepareSubsequentHandover", gsmmap.OpCodePrepareSubsequentHandover, int64(gsm_map.PrepareSubsequentHandover)},
	{"OpCodeProvideSubscriberInfo", gsmmap.OpCodeProvideSubscriberInfo, int64(gsm_map.ProvideSubscriberInfo)},
	{"OpCodeAnyTimeInterrogation", gsmmap.OpCodeAnyTimeInterrogation, int64(gsm_map.AnyTimeInterrogation)},
	{"OpCodeSSInvocationNotification", gsmmap.OpCodeSSInvocationNotification, int64(gsm_map.SsInvocationNotification)},
	{"OpCodeSetReportingState", gsmmap.OpCodeSetReportingState, int64(gsm_map.SetReportingState)},
	{"OpCodeStatusReport", gsmmap.OpCodeStatusReport, int64(gsm_map.StatusReport)},
	{"OpCodeRemoteUserFree", gsmmap.OpCodeRemoteUserFree, int64(gsm_map.RemoteUserFree)},
	{"OpCodeRegisterCCEntry", gsmmap.OpCodeRegisterCCEntry, int64(gsm_map.RegisterCCEntry)},
	{"OpCodeEraseCCEntry", gsmmap.OpCodeEraseCCEntry, int64(gsm_map.EraseCCEntry)},
	{"OpCodeProvideSubscriberLocation", gsmmap.OpCodeProvideSubscriberLocation, int64(gsm_map.ProvideSubscriberLocation)},
	{"OpCodeSendGroupCallInfo", gsmmap.OpCodeSendGroupCallInfo, int64(gsm_map.SendGroupCallInfo)},
	{"OpCodeSendRoutingInfoForLCS", gsmmap.OpCodeSendRoutingInfoForLCS, int64(gsm_map.SendRoutingInfoForLCS)},
	{"OpCodeSubscriberLocationReport", gsmmap.OpCodeSubscriberLocationReport, int64(gsm_map.SubscriberLocationReport)},
	{"OpCodeISTAlert", gsmmap.OpCodeISTAlert, int64(gsm_map.IstAlert)},
	{"OpCodeISTCommand", gsmmap.OpCodeISTCommand, int64(gsm_map.IstCommand)},
	{"OpCodeNoteMMEvent", gsmmap.OpCodeNoteMMEvent, int64(gsm_map.NoteMMEvent)},
	{"OpCodeSendParameters", gsmmap.OpCodeSendParameters, 9},
	{"OpCodeProcessUnstructuredSSData", gsmmap.OpCodeProcessUnstructuredSSData, 19},
	{"OpCodePerformHandover", gsmmap.OpCodePerformHandover, 28},
	{"OpCodePerformSubsequentHandover", gsmmap.OpCodePerformSubsequentHandover, 30},
	{"OpCodeProvideSIWFSNumber", gsmmap.OpCodeProvideSIWFSNumber, 31},
	{"OpCodeSIWFSSignallingModify", gsmmap.OpCodeSIWFSSignallingModify, 32},
	{"OpCodeNoteInternalHandover", gsmmap.OpCodeNoteInternalHandover, 35},
	{"OpCodeNoteSubscriberPresent", gsmmap.OpCodeNoteSubscriberPresent, 48},
	{"OpCodeAlertServiceCentreWithoutResult", gsmmap.OpCodeAlertServiceCentreWithoutResult, 49},
	{"OpCodeTraceSubscriberActivity", gsmmap.OpCodeTraceSubscriberActivity, 52},
	{"OpCodeBeginSubscriberActivity", gsmmap.OpCodeBeginSubscriberActivity, 54},
}

// errorCodes uses the same catalogue and historical reservations as operationCodes.
var errorCodes = []codeCase{
	{"ErrorCodeUnknownSubscriber", gsmmap.ErrorCodeUnknownSubscriber, int64(gsm_map.UnknownSubscriber)},
	{"ErrorCodeUnknownMSC", gsmmap.ErrorCodeUnknownMSC, int64(gsm_map.UnknownMSC)},
	{"ErrorCodeUnidentifiedSubscriber", gsmmap.ErrorCodeUnidentifiedSubscriber, int64(gsm_map.UnidentifiedSubscriber)},
	{"ErrorCodeAbsentSubscriberSM", gsmmap.ErrorCodeAbsentSubscriberSM, int64(gsm_map.AbsentSubscriberSM)},
	{"ErrorCodeUnknownEquipment", gsmmap.ErrorCodeUnknownEquipment, int64(gsm_map.UnknownEquipment)},
	{"ErrorCodeRoamingNotAllowed", gsmmap.ErrorCodeRoamingNotAllowed, int64(gsm_map.RoamingNotAllowed)},
	{"ErrorCodeIllegalSubscriber", gsmmap.ErrorCodeIllegalSubscriber, int64(gsm_map.IllegalSubscriber)},
	{"ErrorCodeBearerServiceNotProvisioned", gsmmap.ErrorCodeBearerServiceNotProvisioned, int64(gsm_map.BearerServiceNotProvisioned)},
	{"ErrorCodeTeleserviceNotProvisioned", gsmmap.ErrorCodeTeleserviceNotProvisioned, int64(gsm_map.TeleserviceNotProvisioned)},
	{"ErrorCodeIllegalEquipment", gsmmap.ErrorCodeIllegalEquipment, int64(gsm_map.IllegalEquipment)},
	{"ErrorCodeCallBarred", gsmmap.ErrorCodeCallBarred, int64(gsm_map.CallBarred)},
	{"ErrorCodeForwardingViolation", gsmmap.ErrorCodeForwardingViolation, int64(gsm_map.ForwardingViolation)},
	{"ErrorCodeCUGReject", gsmmap.ErrorCodeCUGReject, int64(gsm_map.CugReject)},
	{"ErrorCodeIllegalSSOperation", gsmmap.ErrorCodeIllegalSSOperation, int64(gsm_map.IllegalSSOperation)},
	{"ErrorCodeSSErrorStatus", gsmmap.ErrorCodeSSErrorStatus, int64(gsm_map.SsErrorStatus)},
	{"ErrorCodeSSNotAvailable", gsmmap.ErrorCodeSSNotAvailable, int64(gsm_map.SsNotAvailable)},
	{"ErrorCodeSSSubscriptionViolation", gsmmap.ErrorCodeSSSubscriptionViolation, int64(gsm_map.SsSubscriptionViolation)},
	{"ErrorCodeSSIncompatibility", gsmmap.ErrorCodeSSIncompatibility, int64(gsm_map.SsIncompatibility)},
	{"ErrorCodeFacilityNotSupported", gsmmap.ErrorCodeFacilityNotSupported, int64(gsm_map.FacilityNotSupported)},
	{"ErrorCodeOngoingGroupCall", gsmmap.ErrorCodeOngoingGroupCall, int64(gsm_map.OngoingGroupCall)},
	{"ErrorCodeNoHandoverNumberAvailable", gsmmap.ErrorCodeNoHandoverNumberAvailable, int64(gsm_map.NoHandoverNumberAvailable)},
	{"ErrorCodeSubsequentHandoverFailure", gsmmap.ErrorCodeSubsequentHandoverFailure, int64(gsm_map.SubsequentHandoverFailure)},
	{"ErrorCodeAbsentSubscriber", gsmmap.ErrorCodeAbsentSubscriber, int64(gsm_map.AbsentSubscriber)},
	{"ErrorCodeIncompatibleTerminal", gsmmap.ErrorCodeIncompatibleTerminal, int64(gsm_map.IncompatibleTerminal)},
	{"ErrorCodeShortTermDenial", gsmmap.ErrorCodeShortTermDenial, int64(gsm_map.ShortTermDenial)},
	{"ErrorCodeLongTermDenial", gsmmap.ErrorCodeLongTermDenial, int64(gsm_map.LongTermDenial)},
	{"ErrorCodeSubscriberBusyForMTSMS", gsmmap.ErrorCodeSubscriberBusyForMTSMS, int64(gsm_map.SubscriberBusyForMTSMS)},
	{"ErrorCodeSMDeliveryFailure", gsmmap.ErrorCodeSMDeliveryFailure, int64(gsm_map.SmDeliveryFailure)},
	{"ErrorCodeMessageWaitingListFull", gsmmap.ErrorCodeMessageWaitingListFull, int64(gsm_map.MessageWaitingListFull)},
	{"ErrorCodeSystemFailure", gsmmap.ErrorCodeSystemFailure, int64(gsm_map.SystemFailure)},
	{"ErrorCodeDataMissing", gsmmap.ErrorCodeDataMissing, int64(gsm_map.DataMissing)},
	{"ErrorCodeUnexpectedDataValue", gsmmap.ErrorCodeUnexpectedDataValue, int64(gsm_map.UnexpectedDataValue)},
	{"ErrorCodePWRegistrationFailure", gsmmap.ErrorCodePWRegistrationFailure, int64(gsm_map.PwRegistrationFailure)},
	{"ErrorCodeNegativePWCheck", gsmmap.ErrorCodeNegativePWCheck, int64(gsm_map.NegativePWCheck)},
	{"ErrorCodeNoRoamingNumberAvailable", gsmmap.ErrorCodeNoRoamingNumberAvailable, int64(gsm_map.NoRoamingNumberAvailable)},
	{"ErrorCodeTracingBufferFull", gsmmap.ErrorCodeTracingBufferFull, int64(gsm_map.TracingBufferFull)},
	{"ErrorCodeTargetCellOutsideGroupCallArea", gsmmap.ErrorCodeTargetCellOutsideGroupCallArea, int64(gsm_map.TargetCellOutsideGroupCallArea)},
	{"ErrorCodeNumberOfPWAttemptsViolation", gsmmap.ErrorCodeNumberOfPWAttemptsViolation, int64(gsm_map.NumberOfPWAttemptsViolation)},
	{"ErrorCodeNumberChanged", gsmmap.ErrorCodeNumberChanged, int64(gsm_map.NumberChanged)},
	{"ErrorCodeBusySubscriber", gsmmap.ErrorCodeBusySubscriber, int64(gsm_map.BusySubscriber)},
	{"ErrorCodeNoSubscriberReply", gsmmap.ErrorCodeNoSubscriberReply, int64(gsm_map.NoSubscriberReply)},
	{"ErrorCodeForwardingFailed", gsmmap.ErrorCodeForwardingFailed, int64(gsm_map.ForwardingFailed)},
	{"ErrorCodeORNotAllowed", gsmmap.ErrorCodeORNotAllowed, int64(gsm_map.OrNotAllowed)},
	{"ErrorCodeATINotAllowed", gsmmap.ErrorCodeATINotAllowed, int64(gsm_map.AtiNotAllowed)},
	{"ErrorCodeNoGroupCallNumberAvailable", gsmmap.ErrorCodeNoGroupCallNumberAvailable, int64(gsm_map.NoGroupCallNumberAvailable)},
	{"ErrorCodeResourceLimitation", gsmmap.ErrorCodeResourceLimitation, int64(gsm_map.ResourceLimitation)},
	{"ErrorCodeUnauthorizedRequestingNetwork", gsmmap.ErrorCodeUnauthorizedRequestingNetwork, int64(gsm_map.UnauthorizedRequestingNetwork)},
	{"ErrorCodeUnauthorizedLCSClient", gsmmap.ErrorCodeUnauthorizedLCSClient, int64(gsm_map.UnauthorizedLCSClient)},
	{"ErrorCodePositionMethodFailure", gsmmap.ErrorCodePositionMethodFailure, int64(gsm_map.PositionMethodFailure)},
	{"ErrorCodeUnknownOrUnreachableLCSClient", gsmmap.ErrorCodeUnknownOrUnreachableLCSClient, int64(gsm_map.UnknownOrUnreachableLCSClient)},
	{"ErrorCodeMMEventNotSupported", gsmmap.ErrorCodeMMEventNotSupported, int64(gsm_map.MmEventNotSupported)},
	{"ErrorCodeATSINotAllowed", gsmmap.ErrorCodeATSINotAllowed, int64(gsm_map.AtsiNotAllowed)},
	{"ErrorCodeATMNotAllowed", gsmmap.ErrorCodeATMNotAllowed, int64(gsm_map.AtmNotAllowed)},
	{"ErrorCodeInformationNotAvailable", gsmmap.ErrorCodeInformationNotAvailable, int64(gsm_map.InformationNotAvailable)},
	{"ErrorCodeUnknownAlphabet", gsmmap.ErrorCodeUnknownAlphabet, int64(gsm_map.UnknownAlphabet)},
	{"ErrorCodeUSSDBusy", gsmmap.ErrorCodeUSSDBusy, int64(gsm_map.UssdBusy)},
	{"ErrorCodeUnknownBaseStation", gsmmap.ErrorCodeUnknownBaseStation, 2},
	{"ErrorCodeInvalidTargetBaseStation", gsmmap.ErrorCodeInvalidTargetBaseStation, 23},
	{"ErrorCodeNoRadioResourceAvailable", gsmmap.ErrorCodeNoRadioResourceAvailable, 24},
}

// equivalentContexts lists the application context names that 3GPP TS 29.002
// V19.1.0 clause 17.3.2 assigns to v1- or v2-equivalent application contexts
// without listing them in clause 17.3.3, with their values read from that
// clause.
var equivalentContexts = []struct {
	name  string
	value tcap.OID
	want  tcap.OID
}{
	{"ShortMsgMORelayContextV2", gsmmap.ShortMsgMORelayContextV2, "0.4.0.0.1.0.21.2"}, // clause 17.3.2.22
}
