package camel

import "github.com/gomaja/go-asn1-tcap"

// CAP version 1 application context: GSM 09.78 version 5.6.0 clause 6.5.
// The last arc is the version of the module (version1(0)), not the CAP version.
const (
	GsmSSFToGsmSCFContextV1 tcap.OID = "0.4.0.0.1.0.50.0" // CAP-v1-gsmSSF-to-gsmSCF-AC
)

// CAP version 2 application contexts: GSM 09.78 version 7.1.0 clause 6.6.
// The last arc is the version of the module (version2(1)), not the CAP version.
const (
	GsmSSFToGsmSCFContextV2       tcap.OID = "0.4.0.0.1.0.50.1" // CAP-v2-gsmSSF-to-gsmSCF-AC
	AssistGsmSSFToGsmSCFContextV2 tcap.OID = "0.4.0.0.1.0.51.1" // CAP-v2-assist-gsmSSF-to-gsmSCF-AC
	GsmSRFToGsmSCFContextV2       tcap.OID = "0.4.0.0.1.0.52.1" // CAP-v2-gsmSRF-to-gsmSCF-AC
)

// CAP version 3 application contexts (CAMEL phase 3). The first three are
// defined by 3GPP TS 29.078 V4.9.0 clause 5.6; since Release 5 the same ASN.1
// names are bound to the version 4 arcs, so the values below are no longer
// printed in the current text but remain in use by CAMEL phase 3 peers. The
// GPRS and SMS contexts are unchanged in 3GPP TS 29.078 V19.0.0 clause 5.6.
const (
	GsmSSFSCFGenericContextV3       tcap.OID = "0.4.0.0.1.21.3.4"  // id-ac-CAP-gsmSSF-scfGenericAC
	GsmSSFSCFAssistHandoffContextV3 tcap.OID = "0.4.0.0.1.21.3.6"  // id-ac-CAP-gsmSSF-scfAssistHandoffAC
	GsmSRFGsmSCFContextV3           tcap.OID = "0.4.0.0.1.20.3.14" // id-ac-gsmSRF-gsmSCF
	GprsSSFGsmSCFContextV3          tcap.OID = "0.4.0.0.1.21.3.50" // id-ac-CAP-gprsSSF-gsmSCF-AC
	GsmSCFGprsSSFContextV3          tcap.OID = "0.4.0.0.1.21.3.51" // id-ac-CAP-gsmSCF-gprsSSF-AC
	SMSContextV3                    tcap.OID = "0.4.0.0.1.21.3.61" // id-ac-cap3-sms-AC
)

// CAP version 4 application contexts: 3GPP TS 29.078 V19.0.0 clause 5.6.
// There is no version 4 GPRS context: the GPRS contexts exist only in version 3.
const (
	GsmSSFSCFGenericContextV4       tcap.OID = "0.4.0.0.1.23.3.4"  // id-ac-CAP-gsmSSF-scfGenericAC
	GsmSSFSCFAssistHandoffContextV4 tcap.OID = "0.4.0.0.1.23.3.6"  // id-ac-CAP-gsmSSF-scfAssistHandoffAC
	SCFGsmSSFGenericContextV4       tcap.OID = "0.4.0.0.1.23.3.8"  // id-ac-CAP-scf-gsmSSFGenericAC
	GsmSRFGsmSCFContextV4           tcap.OID = "0.4.0.0.1.22.3.14" // id-ac-gsmSRF-gsmSCF
	SMSContextV4                    tcap.OID = "0.4.0.0.1.23.3.61" // id-ac-cap4-sms-AC
)
