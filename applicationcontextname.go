package asn1tcapmodel

// AcnVersion definition https://oid-base.com/get/0.4.0.0.1.0.20.3
type AcnVersion int

const (
	_ AcnVersion = iota
	_
	Version2 // version number 2 is added because it is necessary practically
	Version3
)

// ApplicationContextName definitions: https://oid-base.com/get/0.4.0.0.1.0
type ApplicationContextName int

const (
	_ ApplicationContextName = iota
	NetworkLocUpContext
	LocationCancelContext
	RoamingNbEnquiryContext
	IstAlertingContext
	LocInfoRetrievalContext
	CallControlTransferContext
	ReportingContext
	CallCompletionContext
	ImmediateTerminationContext
	ResetContext
	HandoverControlContext
	_
	EquipmentMngtContext
	InfoRetrievalContext
	InterVlrInfoRetrievalContext
	SubscriberDataMngtContext
	TracingContext
	NetworkFunctionalSsContext
	NetworkUnstructuredSSContext
	ShortMsgGatewayContext
	ShortMsgMORelayContext
	SubscriberDataModificationNotificationContext
	ShortMsgAlertContext
	MwdMngtContext
	ShortMsgMTRelayContext
	ImsiRetrievalContext
	MsPurgingContext
	SubscriberInfoEnquiryContext
	AnyTimeInfoEnquiryContext
	_
	GroupCallControlContext
	GprsLocationUpdateContext
	GprsLocationInfoRetrievalContext
	FailureReportContext
	GprsNotifyContext
	SsInvocationNotificationContext
	LocationSvcGatewayContext
	LocationSvcEnquiryContext
	AuthenticationFailureReportContext
	_
	_
	MmEventReportingContext
	AnyTimeInfoHandlingContext
	ResourceManagementContext
	_
	_
	_
	_
	_
	CapGsmssfToGsmscfContext
	CapAssistHandoffGsmssfToGsmscfContext
	CapGsmSRFToGsmscfContext
)

/* https://github.com/boundary/wireshark/blob/master/asn1/gsm_map/MAP-ApplicationContexts.asn
-- The following Object Identifiers are reserved for application-contexts
--  existing in previous versions of the protocol

-- AC Name & Version	Object Identifier
--
-- networkLocUpContext-v1	map-ac networkLocUp (1)	version1 (1)
-- networkLocUpContext-v2	map-ac networkLocUp (1)	version2 (2)
-- locationCancellationContext-v1	map-ac locationCancellation (2)	version1 (1)
-- locationCancellationContext-v2	map-ac locationCancellation (2)	version2 (2)
-- roamingNumberEnquiryContext-v1	map-ac roamingNumberEnquiry (3)	version1 (1)
-- roamingNumberEnquiryContext-v2	map-ac roamingNumberEnquiry (3)	version2 (2)
-- locationInfoRetrievalContext-v1	map-ac locationInfoRetrieval (5)	version1 (1)
-- locationInfoRetrievalContext-v2	map-ac locationInfoRetrieval (5)	version2 (2)
-- resetContext-v1	map-ac reset (10)	version1 (1)
-- resetContext-v2	map-ac reset (10)	version2 (2)
-- handoverControlContext-v1	map-ac handoverControl (11)	version1 (1)
-- handoverControlContext-v2	map-ac handoverControl (11)	version2 (2)
-- sIWFSAllocationContext-v3	map-ac sIWFSAllocation (12)	version3 (3)
-- equipmentMngtContext-v1	map-ac equipmentMngt (13)	version1 (1)
-- equipmentMngtContext-v2	map-ac equipmentMngt (13)	version2 (2)
-- infoRetrievalContext-v1	map-ac infoRetrieval (14)	version1 (1)
-- infoRetrievalContext-v2	map-ac infoRetrieval (14)	version2 (2)
-- interVlrInfoRetrievalContext-v2	map-ac interVlrInfoRetrieval (15)	version2 (2)
-- subscriberDataMngtContext-v1	map-ac subscriberDataMngt (16)	version1 (1)
-- subscriberDataMngtContext-v2	map-ac subscriberDataMngt (16)	version2 (2)
-- tracingContext-v1	map-ac tracing (17)	version1 (1)
-- tracingContext-v2	map-ac tracing (17)	version2 (2)
-- networkFunctionalSsContext-v1	map-ac networkFunctionalSs (18)	version1 (1)
-- shortMsgGatewayContext-v1	map-ac shortMsgGateway (20)	version1 (1)
-- shortMsgGatewayContext-v2	map-ac shortMsgGateway (20)	version2 (2)
-- shortMsgRelayContext-v1	map-ac shortMsgRelay (21)	version1 (1)
-- shortMsgAlertContext-v1	map-ac shortMsgAlert (23)	version1 (1)
-- mwdMngtContext-v1	map-ac mwdMngt (24)	version1 (1)
-- mwdMngtContext-v2	map-ac mwdMngt (24)	version2 (2)
-- shortMsgMT-RelayContext-v2	map-ac shortMsgMT-Relay (25)	version2 (2)
-- msPurgingContext-v2	map-ac msPurging (27)	version2 (2)
-- callControlTransferContext-v3	map-ac callControlTransferContext (6)	version3 (3)
-- gprsLocationInfoRetrievalContext-v3	map-ac gprsLocationInfoRetrievalContext (33) version3 (3)

*/
