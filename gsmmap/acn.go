// Package gsmmap provides GSM-MAP protocol constants for use as TCAP parameters.
//
// These constants represent Application Context Names (ACN) and ACN versions
// as defined in 3GPP TS 29.002 and the OID registry at https://oid-base.com/get/0.4.0.0.1.0
//
// They are used as parameters within TCAP dialogue portions to identify the
// MAP service context of a transaction.
package gsmmap

// AcnVersion represents a GSM-MAP Application Context Name version number.
// Reference: https://oid-base.com/get/0.4.0.0.1.0.20.3
type AcnVersion = int

const (
	Version1 AcnVersion = 1
	Version2 AcnVersion = 2
	Version3 AcnVersion = 3
)

// ApplicationContextName represents a GSM-MAP Application Context Name.
// These values form part of the ACN OID: 0.4.0.0.1.0.<acn>.<version>
// Reference: https://oid-base.com/get/0.4.0.0.1.0
type ApplicationContextName = int

const (
	NetworkLocUpContext                          ApplicationContextName = 1
	LocationCancelContext                        ApplicationContextName = 2
	RoamingNbEnquiryContext                      ApplicationContextName = 3
	IstAlertingContext                           ApplicationContextName = 4
	LocInfoRetrievalContext                      ApplicationContextName = 5
	CallControlTransferContext                   ApplicationContextName = 6
	ReportingContext                             ApplicationContextName = 7
	CallCompletionContext                        ApplicationContextName = 8
	ImmediateTerminationContext                  ApplicationContextName = 9
	ResetContext                                 ApplicationContextName = 10
	HandoverControlContext                       ApplicationContextName = 11
	EquipmentMngtContext                         ApplicationContextName = 13
	InfoRetrievalContext                         ApplicationContextName = 14
	InterVlrInfoRetrievalContext                 ApplicationContextName = 15
	SubscriberDataMngtContext                    ApplicationContextName = 16
	TracingContext                               ApplicationContextName = 17
	NetworkFunctionalSsContext                   ApplicationContextName = 18
	NetworkUnstructuredSSContext                  ApplicationContextName = 19
	ShortMsgGatewayContext                       ApplicationContextName = 20
	ShortMsgMORelayContext                       ApplicationContextName = 21
	SubscriberDataModificationNotificationContext ApplicationContextName = 22
	ShortMsgAlertContext                         ApplicationContextName = 23
	MwdMngtContext                               ApplicationContextName = 24
	ShortMsgMTRelayContext                       ApplicationContextName = 25
	ImsiRetrievalContext                         ApplicationContextName = 26
	MsPurgingContext                             ApplicationContextName = 27
	SubscriberInfoEnquiryContext                 ApplicationContextName = 28
	AnyTimeInfoEnquiryContext                    ApplicationContextName = 29
	GroupCallControlContext                      ApplicationContextName = 31
	GprsLocationUpdateContext                    ApplicationContextName = 32
	GprsLocationInfoRetrievalContext             ApplicationContextName = 33
	FailureReportContext                         ApplicationContextName = 34
	GprsNotifyContext                            ApplicationContextName = 35
	SsInvocationNotificationContext              ApplicationContextName = 36
	LocationSvcGatewayContext                    ApplicationContextName = 37
	LocationSvcEnquiryContext                    ApplicationContextName = 38
	AuthenticationFailureReportContext           ApplicationContextName = 39
	MmEventReportingContext                      ApplicationContextName = 42
	AnyTimeInfoHandlingContext                   ApplicationContextName = 43
	ResourceManagementContext                    ApplicationContextName = 44
)

/*
Reference: https://github.com/boundary/wireshark/blob/master/asn1/gsm_map/MAP-ApplicationContexts.asn

The following Object Identifiers are reserved for application-contexts
existing in previous versions of the protocol:

AC Name & Version				Object Identifier

networkLocUpContext-v1			map-ac networkLocUp (1)			version1 (1)
networkLocUpContext-v2			map-ac networkLocUp (1)			version2 (2)
locationCancellationContext-v1	map-ac locationCancellation (2)	version1 (1)
locationCancellationContext-v2	map-ac locationCancellation (2)	version2 (2)
roamingNumberEnquiryContext-v1	map-ac roamingNumberEnquiry (3)	version1 (1)
roamingNumberEnquiryContext-v2	map-ac roamingNumberEnquiry (3)	version2 (2)
locationInfoRetrievalContext-v1	map-ac locationInfoRetrieval (5)	version1 (1)
locationInfoRetrievalContext-v2	map-ac locationInfoRetrieval (5)	version2 (2)
resetContext-v1					map-ac reset (10)				version1 (1)
resetContext-v2					map-ac reset (10)				version2 (2)
handoverControlContext-v1		map-ac handoverControl (11)		version1 (1)
handoverControlContext-v2		map-ac handoverControl (11)		version2 (2)
sIWFSAllocationContext-v3		map-ac sIWFSAllocation (12)		version3 (3)
equipmentMngtContext-v1			map-ac equipmentMngt (13)		version1 (1)
equipmentMngtContext-v2			map-ac equipmentMngt (13)		version2 (2)
infoRetrievalContext-v1			map-ac infoRetrieval (14)		version1 (1)
infoRetrievalContext-v2			map-ac infoRetrieval (14)		version2 (2)
interVlrInfoRetrievalContext-v2	map-ac interVlrInfoRetrieval (15)	version2 (2)
subscriberDataMngtContext-v1	map-ac subscriberDataMngt (16)	version1 (1)
subscriberDataMngtContext-v2	map-ac subscriberDataMngt (16)	version2 (2)
tracingContext-v1				map-ac tracing (17)				version1 (1)
tracingContext-v2				map-ac tracing (17)				version2 (2)
networkFunctionalSsContext-v1	map-ac networkFunctionalSs (18)	version1 (1)
shortMsgGatewayContext-v1		map-ac shortMsgGateway (20)		version1 (1)
shortMsgGatewayContext-v2		map-ac shortMsgGateway (20)		version2 (2)
shortMsgRelayContext-v1			map-ac shortMsgRelay (21)		version1 (1)
shortMsgAlertContext-v1			map-ac shortMsgAlert (23)		version1 (1)
mwdMngtContext-v1				map-ac mwdMngt (24)				version1 (1)
mwdMngtContext-v2				map-ac mwdMngt (24)				version2 (2)
shortMsgMT-RelayContext-v2		map-ac shortMsgMT-Relay (25)	version2 (2)
msPurgingContext-v2				map-ac msPurging (27)			version2 (2)
callControlTransferContext-v3	map-ac callControlTransferContext (6)	version3 (3)
gprsLocationInfoRetrievalContext-v3	map-ac gprsLocationInfoRetrievalContext (33) version3 (3)
*/
