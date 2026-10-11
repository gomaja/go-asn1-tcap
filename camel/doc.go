// Package camel holds the TCAP parameters of the CAMEL Application Part (CAP)
// as defined by 3GPP TS 29.078 V19.0.0 (Release 19) and, for versions 1 and
// 2, by GSM 09.78: the application context names that CAP carries in the
// dialogue portion, the user-information abstract syntax names of the
// dialogue portion, and the operation codes and error codes that CAP carries
// in the components.
//
// Application contexts are tcap.OID constants with one block per CAP version
// (1 to 4), each with its source. The GPRS contexts exist only in version 3;
// they have no version 4 counterpart. From Release 5 on, TS 29.078 binds the
// ASN.1 names of three version 3 contexts to the version 4 arcs, so the same
// ASN.1 name appears in the version 3 and version 4 blocks with different
// values.
//
// Operation codes and error codes are tcap.LocalCode constants named
// OpCode<Name> and ErrorCode<Name>, taken from the modules CAP-operationcodes
// (clause 5.3) and CAP-errorcodes (clause 5.4) of TS 29.078 V19.0.0. CAP
// versions 1 and 2 (GSM 09.78) use the same values for every code they
// define; GSM 09.78 spells errcode-canceled as "cancelled". Each constant
// carries its ASN.1 name as a trailing comment.
//
// The package holds constants only.
package camel
