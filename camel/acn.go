// Package camel provides CAMEL Application Part (CAP) protocol constants
// for use as TCAP parameters.
//
// These constants represent Application Context Names (ACN) as defined in
// 3GPP TS 29.078 (CAMEL Application Part) and the OID registry.
//
// They are used as parameters within TCAP dialogue portions to identify the
// CAP service context of a transaction.
package camel

// ApplicationContextName represents a CAMEL Application Context Name.
// These values form part of the ACN OID: 0.4.0.0.1.0.<acn>.<version>
type ApplicationContextName = int

const (
	CapGsmssfToGsmscfContext             ApplicationContextName = 50
	CapAssistHandoffGsmssfToGsmscfContext ApplicationContextName = 51
	CapGsmSRFToGsmscfContext             ApplicationContextName = 52
)
