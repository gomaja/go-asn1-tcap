// Package gsmmap holds the TCAP parameters of the Mobile Application Part
// (MAP) as defined by 3GPP TS 29.002 V19.1.0 (Release 19): the application
// context names that MAP carries in the dialogue portion, the operation codes
// and error codes that MAP carries in the components, and the dialogue
// abstract syntax name (DialogueAS) of the MAP dialogue PDUs carried as user
// information.
//
// Application contexts are tcap.OID constants named after the ASN.1 module
// MAP-ApplicationContexts (clause 17.3.3). Operation codes and error codes
// are tcap.LocalCode constants named OpCode<Name> and ErrorCode<Name>
// (clauses 17.5 and 17.6). Each constant carries its ASN.1 name as a
// trailing comment. Each kind has a block of current values and a block of
// values that TS 29.002 reserves for previous versions of the protocol.
//
// Version 1 application contexts model "the behaviour of a MAP V1
// implementation according to the latest phase 1 version of GSM 09.02"
// (clause 14.4), which is V3.11.0. That edition assigns some of these codes
// to other operations and errors (its clause 6.5): operation code 6,
// OpCodeResumeCallHandling here, is attachIMSI there. go-asn1's
// telecom/ss7/gsm_map/gsm0902_v3_11_0 package holds that edition's codes,
// and gsm0902_v4_19_1 those of V4.19.1, the last Phase 2 edition.
//
// The package holds constants only.
package gsmmap
