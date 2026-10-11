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
// The package holds constants only.
package gsmmap
