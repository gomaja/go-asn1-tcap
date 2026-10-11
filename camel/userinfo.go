package camel

import "github.com/gomaja/go-asn1-tcap"

// User-information abstract syntaxes of CAP, carried in the dialogue portion:
// id-CAP-U-ABORT-Reason is defined in 3GPP TS 29.078 V19.0.0 clause 5.7 and
// id-CAP-GPRS-ReferenceNumber in clause 8.1.1.
const (
	UAbortReasonAS        tcap.OID = "0.4.0.0.1.1.2.2" // id-CAP-U-ABORT-Reason
	GPRSReferenceNumberAS tcap.OID = "0.4.0.0.1.1.5.2" // id-CAP-GPRS-ReferenceNumber
)
