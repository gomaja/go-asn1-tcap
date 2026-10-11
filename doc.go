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
// Marshal applies the sender rules: the ASN.1 constraints of Q.773, the
// encoding restrictions of Q.773 clause 4.1.1, and the mapping of dialogue
// PDUs to messages in ITU-T Q.774 (06/97) Table 3. Parse applies the receiver
// rules: it rejects every encoding that is not a valid TCAP message under
// Q.773, and every dialogue PDU that cannot appear in the received message
// type. Rules that depend on transaction or dialogue state (for example that
// an AARE only appears in the first backward Continue) are left to the TCAP
// stack built on this package.
//
// ASN.1 size and value constraints are reported as *ber.ConstraintError from
// github.com/gomaja/go-asn1/runtime/ber, use errors.As. Other violations are
// reported with the Err sentinels of this package, use errors.Is. Every error
// returned by Parse is a *ParseError, which also tells a stack which portion
// of the message failed and which transaction IDs were derivable, as needed
// for the abnormal procedures of Q.774 clauses 3.2.2 and 3.3.4.
//
// The values of TCAP protocol elements (P-Abort causes, problem codes,
// associate results and diagnostics, abort sources) are the generated types
// of github.com/gomaja/go-asn1/telecom/ss7/tcap. Application context names,
// operation codes and error codes of MAP and CAP are in the subpackages
// gsmmap and camel.
package tcap
