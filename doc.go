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
// mapping of dialogue PDUs to messages in ITU-T Q.774 (06/97) Table 3. It
// encodes transaction and dialogue fields with definite lengths, in the short
// form below 128 octets and otherwise in the fewest octets, and strings in
// primitive form (Q.773 clause 4.1.1). Marshal takes no options and encodes
// strictly.
//
// Parse applies the receiver rules. By default it accepts BER with the
// restrictions of Q.773 clause 4.1.1: lengths below 128 octets in the short
// form, long-form lengths in the fewest octets, and OCTET STRING and BIT
// STRING values in primitive form; indefinite lengths of constructed values
// are accepted. WithTolerance also accepts other valid BER encodings and
// values outside ASN.1 constraints, and records each violation in the
// ber.ViolationLog when Parse succeeds. Both modes enforce Q.774 Table 3:
// AARQ only in Begin; AARE with result accepted in Continue or End; AARE with
// another result, or ABRT, in Abort; AUDT only in Unidirectional; Opaque in
// any message. Rules that depend on transaction or dialogue state (for
// example that an AARE only appears in the first backward Continue) are left
// to the TCAP stack.
//
// Parameters and the single-ASN1-type contents of an EXTERNAL keep the BER
// bytes they were given or received. Parse and Marshal check the lengths
// inside them, and the form of every universal OCTET STRING and BIT STRING,
// against Q.773 clause 4.1.1. They cannot check the form of a string under
// another tag, whose type only the TC-user knows, nor the octet-aligned and
// arbitrary encodings of an EXTERNAL. A message parsed with WithTolerance
// whose parameters or EXTERNAL contents break clause 4.1.1 does not marshal
// until the TC-user corrects them.
//
// ASN.1 size and value constraints are reported as *ber.ValidationError from
// github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber; use errors.As.
// Malformed BER, including parameter and EXTERNAL single-ASN1-type bytes,
// is reported with codec errors such as ber.ErrTruncated or *ber.ElementError.
// The rules this package checks itself are reported with its Err sentinels;
// use errors.Is. Marshal wraps them in a FieldError that names the field.
// Other codec failures, such as an unexpected tag or a missing field, keep
// the codec's error and match no sentinel of this package. Every
// error returned by Parse because of the data is a *ParseError, which also
// tells a stack which portion of the message failed and which transaction IDs
// were derivable, as needed for the abnormal procedures of Q.774 clauses
// 3.2.2 and 3.3.4. An invalid ParseOption returns an error wrapping
// ErrInvalidParseOption instead.
//
// The codec checks that every component ID is present where required and
// lies in -128..127 (Q.773 clause 4.2.2.2). Under WithTolerance, an ID that
// does not fit in an int64 returns ErrUnrepresentableValue, and a NULL ID
// where one is required returns ErrMissingInvokeID or ErrInvalidLinkedID.
//
// When the codec cannot decode a message, Parse inspects it for the context
// that Q.774 clauses 3.2.2 and 3.3.4 and Tables 5 and 7 need: the transaction
// IDs, taken from the codec's *wire.DecodeError where it has them, and the
// first failing dialogue portion or component. Inspection stays within the
// decode limits. The ParseError's Err is the failure of that dialogue portion
// or component, or else the codec's *wire.DecodeError.
//
// The codec decodes the dialogue-as and uniDialogue-as abstract syntaxes into
// AARQ, AARE, ABRT and AUDT; a dialogue portion in any other abstract syntax
// is an Opaque EXTERNAL. The codec also applies Q.773 clause 4.2.3: a
// Unidirectional carries AUDT, and the other messages do not. Under
// WithTolerance, Parse accepts a Unidirectional with an Opaque dialogue
// portion and records the violation. When Marshal encodes an AARQ, AARE or
// AUDT, it leaves out a protocol-version equal to {version1}, its DEFAULT.
// When it encodes a BIT STRING, it clears the unused bits of the last octet
// without changing the caller's value.
//
// The values of TCAP protocol elements (P-Abort causes, problem codes,
// associate results and diagnostics, abort sources) are the generated types
// of github.com/gomaja/go-asn1/telecom/ss7/tcap. Application context names,
// operation codes and error codes of MAP and CAP are in the subpackages
// gsmmap and camel.
package tcap
