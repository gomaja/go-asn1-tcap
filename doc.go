// Package tcap encodes and decodes ITU-T Transaction Capabilities Application
// Part (TCAP) messages, as defined by ITU-T Q.773 (06/97) "Transaction
// capabilities formats and encoding", using the generated codec of
// github.com/gomaja/go-asn1.
//
// # Messages
//
// A TCAP message is one of *Begin, *Continue, *End, *Abort and
// *Unidirectional. Build one as a struct literal and call Marshal; decode one
// with Parse and a type switch:
//
//	msg, err := tcap.Parse(data)
//	if err != nil {
//		return err
//	}
//	switch m := msg.(type) {
//	case *tcap.Begin:
//		// m.OTID, m.Dialogue, m.Components
//	case *tcap.Abort:
//		// m.DTID, m.PAbortCause or m.Dialogue
//	}
//
// Components follow the ROS-based component portion of Q.773 (06/97) clause
// 3.1 and Annex A, with ITU-T X.880 (07/94) PDUs. Operation and error codes
// are local integers (LocalCode) or object identifiers (GlobalCode).
// Parameters are carried as the complete BER encoding of one value; their
// abstract syntax belongs to the TC-user (MAP, CAP, INAP, ...).
//
// The dialogue portion (Q.773 clause 3.2 and 4.2.3) is decoded into the
// structured dialogue PDUs AARQ, AARE and ABRT, the unstructured dialogue PDU
// AUDT, or, for any other abstract syntax, an opaque EXTERNAL.
//
// # Strictness
//
// Marshal applies the sender rules: the ASN.1 constraints of Q.773 and the
// mapping of dialogue PDUs to messages in ITU-T Q.774 (06/97) Table 3. What
// it encodes itself uses definite lengths, which Q.773 clause 4.1.1 requires
// in the short form below 128 octets and otherwise in the fewest octets, and
// primitive strings; clause 4.1.2.3 would also allow indefinite lengths.
// Parameters and other values in the abstract syntax of the TC-user are
// encoded as given.
//
// Parse applies the receiver rules: it accepts any valid BER encoding of a
// TCAP message and rejects everything else, including every dialogue PDU
// that cannot appear in the received message type. Rules that depend on
// transaction or dialogue state (for example that an AARE only appears in the
// first backward Continue) are left to the TCAP stack built on this package.
//
// ASN.1 size and value constraints are reported as *ber.ConstraintError from
// github.com/gomaja/go-asn1/runtime/ber, use errors.As. Malformed BER,
// including parameter and EXTERNAL single-ASN1-type bytes, is reported with
// the errors of the codec, such as ber.ErrTruncated or *ber.ElementError.
// Other violations are reported with the Err sentinels of this package, use
// errors.Is; Marshal wraps them in a FieldError that names the field. Every
// error returned by Parse because of the data is a *ParseError, which also
// tells a stack which portion of the message failed and which transaction IDs
// were derivable, as needed for the abnormal procedures of Q.774 clauses
// 3.2.2 and 3.3.4. An invalid ParseOption returns an error wrapping
// ErrInvalidParseOption instead.
//
// The codec checks Invoke IDs. This package checks linked IDs and the invoke
// IDs of ReturnResult, ReturnError and Reject against -128..127 (ITU-T Q.773
// (06/97) clauses 3.1 and 4.2.2.2), because the ASN.1 of Q.773 Annex A
// constrains only the ID of an Invoke. WithConstraintTolerance makes Parse
// accept and record out-of-range IDs of both kinds; Marshal stays strict.
//
// BIT STRING values are encoded as given, and the codec rejects invalid ones.
// Parse clears the unused bits it receives (ITU-T X.690 (02/2021) clause
// 8.6.2.2), so a parsed message can be marshalled again.
//
// The values of TCAP protocol elements (P-Abort causes, problem codes,
// associate results and diagnostics, abort sources) are the generated types
// of github.com/gomaja/go-asn1/telecom/ss7/tcap. Application context names,
// operation codes and error codes of MAP and CAP are in the subpackages
// gsmmap and camel.
package tcap
