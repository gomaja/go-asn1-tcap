package gsmmap

import "github.com/gomaja/go-asn1-tcap"

// Application context names currently defined for MAP, one for each
// (context, version) pair of 3GPP TS 29.002 V19.1.0 clause 17.3.3, module
// MAP-ApplicationContexts. They are the values of the application-context-name
// of the dialogue portion.
const (
	NetworkLocUpContextV3                           tcap.OID = "0.4.0.0.1.0.1.3"  // networkLocUpContext-v3
	LocationCancellationContextV3                   tcap.OID = "0.4.0.0.1.0.2.3"  // locationCancellationContext-v3
	RoamingNumberEnquiryContextV3                   tcap.OID = "0.4.0.0.1.0.3.3"  // roamingNumberEnquiryContext-v3
	AuthenticationFailureReportContextV3            tcap.OID = "0.4.0.0.1.0.39.3" // authenticationFailureReportContext-v3
	LocationInfoRetrievalContextV3                  tcap.OID = "0.4.0.0.1.0.5.3"  // locationInfoRetrievalContext-v3
	ResetContextV3                                  tcap.OID = "0.4.0.0.1.0.10.3" // resetContext-v3
	HandoverControlContextV3                        tcap.OID = "0.4.0.0.1.0.11.3" // handoverControlContext-v3
	EquipmentMngtContextV3                          tcap.OID = "0.4.0.0.1.0.13.3" // equipmentMngtContext-v3
	InfoRetrievalContextV3                          tcap.OID = "0.4.0.0.1.0.14.3" // infoRetrievalContext-v3
	InterVlrInfoRetrievalContextV3                  tcap.OID = "0.4.0.0.1.0.15.3" // interVlrInfoRetrievalContext-v3
	SubscriberDataMngtContextV3                     tcap.OID = "0.4.0.0.1.0.16.3" // subscriberDataMngtContext-v3
	TracingContextV3                                tcap.OID = "0.4.0.0.1.0.17.3" // tracingContext-v3
	NetworkFunctionalSsContextV2                    tcap.OID = "0.4.0.0.1.0.18.2" // networkFunctionalSsContext-v2
	NetworkUnstructuredSsContextV2                  tcap.OID = "0.4.0.0.1.0.19.2" // networkUnstructuredSsContext-v2
	ShortMsgGatewayContextV3                        tcap.OID = "0.4.0.0.1.0.20.3" // shortMsgGatewayContext-v3
	ShortMsgMORelayContextV3                        tcap.OID = "0.4.0.0.1.0.21.3" // shortMsgMO-RelayContext-v3
	ShortMsgAlertContextV2                          tcap.OID = "0.4.0.0.1.0.23.2" // shortMsgAlertContext-v2
	MwdMngtContextV3                                tcap.OID = "0.4.0.0.1.0.24.3" // mwdMngtContext-v3
	ShortMsgMTRelayContextV3                        tcap.OID = "0.4.0.0.1.0.25.3" // shortMsgMT-RelayContext-v3
	ShortMsgMTRelayVGCSContextV3                    tcap.OID = "0.4.0.0.1.0.41.3" // shortMsgMT-Relay-VGCS-Context-v3
	ImsiRetrievalContextV2                          tcap.OID = "0.4.0.0.1.0.26.2" // imsiRetrievalContext-v2
	MsPurgingContextV3                              tcap.OID = "0.4.0.0.1.0.27.3" // msPurgingContext-v3
	SubscriberInfoEnquiryContextV3                  tcap.OID = "0.4.0.0.1.0.28.3" // subscriberInfoEnquiryContext-v3
	AnyTimeInfoEnquiryContextV3                     tcap.OID = "0.4.0.0.1.0.29.3" // anyTimeInfoEnquiryContext-v3
	CallControlTransferContextV4                    tcap.OID = "0.4.0.0.1.0.6.4"  // callControlTransferContext-v4
	SSInvocationNotificationContextV3               tcap.OID = "0.4.0.0.1.0.36.3" // ss-InvocationNotificationContext-v3
	GroupCallControlContextV3                       tcap.OID = "0.4.0.0.1.0.31.3" // groupCallControlContext-v3
	GroupCallInfoRetrievalContextV3                 tcap.OID = "0.4.0.0.1.0.45.3" // groupCallInfoRetrievalContext-v3
	GprsLocationUpdateContextV3                     tcap.OID = "0.4.0.0.1.0.32.3" // gprsLocationUpdateContext-v3
	GprsLocationInfoRetrievalContextV4              tcap.OID = "0.4.0.0.1.0.33.4" // gprsLocationInfoRetrievalContext-v4
	FailureReportContextV3                          tcap.OID = "0.4.0.0.1.0.34.3" // failureReportContext-v3
	GprsNotifyContextV3                             tcap.OID = "0.4.0.0.1.0.35.3" // gprsNotifyContext-v3
	ReportingContextV3                              tcap.OID = "0.4.0.0.1.0.7.3"  // reportingContext-v3
	CallCompletionContextV3                         tcap.OID = "0.4.0.0.1.0.8.3"  // callCompletionContext-v3
	IstAlertingContextV3                            tcap.OID = "0.4.0.0.1.0.4.3"  // istAlertingContext-v3
	ServiceTerminationContextV3                     tcap.OID = "0.4.0.0.1.0.9.3"  // serviceTerminationContext-v3
	LocationSvcGatewayContextV3                     tcap.OID = "0.4.0.0.1.0.37.3" // locationSvcGatewayContext-v3
	LocationSvcEnquiryContextV3                     tcap.OID = "0.4.0.0.1.0.38.3" // locationSvcEnquiryContext-v3
	MMEventReportingContextV3                       tcap.OID = "0.4.0.0.1.0.42.3" // mm-EventReportingContext-v3
	AnyTimeInfoHandlingContextV3                    tcap.OID = "0.4.0.0.1.0.43.3" // anyTimeInfoHandlingContext-v3
	SubscriberDataModificationNotificationContextV3 tcap.OID = "0.4.0.0.1.0.22.3" // subscriberDataModificationNotificationContext-v3
	ResourceManagementContextV3                     tcap.OID = "0.4.0.0.1.0.44.3" // resourceManagementContext-v3
	VcsgLocationUpdateContextV3                     tcap.OID = "0.4.0.0.1.0.46.3" // vcsgLocationUpdateContext-v3
	VcsgLocationCancellationContextV3               tcap.OID = "0.4.0.0.1.0.47.3" // vcsgLocationCancellationContext-v3
)

// Object identifiers reserved for application contexts of previous versions of
// the protocol: 3GPP TS 29.002 V19.1.0 clause 17.3.3, module
// MAP-ApplicationContexts, "object identifiers reserved for application
// contexts" existing in previous versions. No current assignment exists for
// them.
//
// A MAP version 1 dialogue carries no application context name on the wire
// (TS 29.002 V19.1.0 clause 15.2.2), so the version 1 values identify contexts
// locally.
const (
	NetworkLocUpContextV1              tcap.OID = "0.4.0.0.1.0.1.1"  // networkLocUpContext-v1
	NetworkLocUpContextV2              tcap.OID = "0.4.0.0.1.0.1.2"  // networkLocUpContext-v2
	LocationCancellationContextV1      tcap.OID = "0.4.0.0.1.0.2.1"  // locationCancellationContext-v1
	LocationCancellationContextV2      tcap.OID = "0.4.0.0.1.0.2.2"  // locationCancellationContext-v2
	RoamingNumberEnquiryContextV1      tcap.OID = "0.4.0.0.1.0.3.1"  // roamingNumberEnquiryContext-v1
	RoamingNumberEnquiryContextV2      tcap.OID = "0.4.0.0.1.0.3.2"  // roamingNumberEnquiryContext-v2
	LocationInfoRetrievalContextV1     tcap.OID = "0.4.0.0.1.0.5.1"  // locationInfoRetrievalContext-v1
	LocationInfoRetrievalContextV2     tcap.OID = "0.4.0.0.1.0.5.2"  // locationInfoRetrievalContext-v2
	ResetContextV1                     tcap.OID = "0.4.0.0.1.0.10.1" // resetContext-v1
	ResetContextV2                     tcap.OID = "0.4.0.0.1.0.10.2" // resetContext-v2
	HandoverControlContextV1           tcap.OID = "0.4.0.0.1.0.11.1" // handoverControlContext-v1
	HandoverControlContextV2           tcap.OID = "0.4.0.0.1.0.11.2" // handoverControlContext-v2
	SIWFSAllocationContextV3           tcap.OID = "0.4.0.0.1.0.12.3" // sIWFSAllocationContext-v3
	EquipmentMngtContextV1             tcap.OID = "0.4.0.0.1.0.13.1" // equipmentMngtContext-v1
	EquipmentMngtContextV2             tcap.OID = "0.4.0.0.1.0.13.2" // equipmentMngtContext-v2
	InfoRetrievalContextV1             tcap.OID = "0.4.0.0.1.0.14.1" // infoRetrievalContext-v1
	InfoRetrievalContextV2             tcap.OID = "0.4.0.0.1.0.14.2" // infoRetrievalContext-v2
	InterVlrInfoRetrievalContextV2     tcap.OID = "0.4.0.0.1.0.15.2" // interVlrInfoRetrievalContext-v2
	SubscriberDataMngtContextV1        tcap.OID = "0.4.0.0.1.0.16.1" // subscriberDataMngtContext-v1
	SubscriberDataMngtContextV2        tcap.OID = "0.4.0.0.1.0.16.2" // subscriberDataMngtContext-v2
	TracingContextV1                   tcap.OID = "0.4.0.0.1.0.17.1" // tracingContext-v1
	TracingContextV2                   tcap.OID = "0.4.0.0.1.0.17.2" // tracingContext-v2
	NetworkFunctionalSsContextV1       tcap.OID = "0.4.0.0.1.0.18.1" // networkFunctionalSsContext-v1
	ShortMsgGatewayContextV1           tcap.OID = "0.4.0.0.1.0.20.1" // shortMsgGatewayContext-v1
	ShortMsgGatewayContextV2           tcap.OID = "0.4.0.0.1.0.20.2" // shortMsgGatewayContext-v2
	ShortMsgRelayContextV1             tcap.OID = "0.4.0.0.1.0.21.1" // shortMsgRelayContext-v1
	ShortMsgAlertContextV1             tcap.OID = "0.4.0.0.1.0.23.1" // shortMsgAlertContext-v1
	MwdMngtContextV1                   tcap.OID = "0.4.0.0.1.0.24.1" // mwdMngtContext-v1
	MwdMngtContextV2                   tcap.OID = "0.4.0.0.1.0.24.2" // mwdMngtContext-v2
	ShortMsgMTRelayContextV2           tcap.OID = "0.4.0.0.1.0.25.2" // shortMsgMT-RelayContext-v2
	MsPurgingContextV2                 tcap.OID = "0.4.0.0.1.0.27.2" // msPurgingContext-v2
	CallControlTransferContextV3       tcap.OID = "0.4.0.0.1.0.6.3"  // callControlTransferContext-v3
	GprsLocationInfoRetrievalContextV3 tcap.OID = "0.4.0.0.1.0.33.3" // gprsLocationInfoRetrievalContext-v3
)
