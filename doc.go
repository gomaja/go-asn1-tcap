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
// The go-asn1 codec checks the ASN.1 of Q.773 Annex A and X.880, the encoding
// rules of X.680 and X.690, and Q.773 clauses 4.1.1, 4.2.2.2 and 4.2.3.
// This package checks dialogue placement and results (ITU-T Q.774 (06/97)
// Table 3), dialogue versions (clause 3.2.3), Table 7 transaction-ID
// derivability and whether values fit its Go model.
//
// Marshal applies the sender rules. It encodes TCAP's own fields with
// definite lengths, in the short form below 128 octets and otherwise in the
// fewest octets, and strings in primitive form (Q.773 clause 4.1.1).
// Marshal takes no options and encodes strictly.
//
// Parse applies the receiver rules. By default it accepts BER with the
// restrictions of Q.773 clause 4.1.1 in TCAP's own syntax: lengths below 128
// octets in the short form, long-form lengths in the fewest octets, and
// OCTET STRING and BIT STRING values in primitive form; indefinite lengths of
// constructed values are accepted. WithTolerance also accepts other valid
// BER encodings and values outside ASN.1 constraints, and records each
// violation in the ViolationLog when Parse succeeds.
//
// This package applies the dialogue rules of Q.774 Table 3 itself, in both
// Parse modes and in Marshal. A Begin carries an AARQ (Figure A.5, sheet 3).
// A Continue or an End carries an AARE with result accepted (Figure A.5,
// sheet 7) or user information in another abstract syntax (clause 3.2.1.2).
// An Abort carries an ABRT, an AARE with result reject-permanent (Table 3,
// Note 3; clauses 3.2.1.2 and 3.2.3), or user information in another
// abstract syntax (Q.773 clause 3.1). An AARE with any other result is
// refused. The codec requires the AUDT in a Unidirectional and keeps its
// abstract syntax out of the other messages (Q.773 clause 4.2.3); under
// WithTolerance, Parse accepts a Unidirectional carrying another abstract
// syntax and records the violation, and Marshal refuses it. Rules that depend
// on transaction or dialogue state, such as whether a Continue or an End may
// still carry its AARE, are left to the TCAP stack.
//
// TCAP's own syntax is the TC message, the component and dialogue syntax,
// and the encoding headers of an EXTERNAL. Parameters and the data values of
// user information and Opaque EXTERNALs are the TC-user's syntax (ITU-T
// X.690 (02/2021) clauses 8.15 and 8.18), which Q.773 clause 4.1.1 does not
// cover. Parameters and single-ASN1-type contents keep the BER bytes they
// were given or received; Parse in either mode and Marshal check only that
// they are well-formed BER. That covers REAL contents (X.690 clause 8.5) and
// the explicit [0] of an EXTERNAL, EMBEDDED PDV or CHARACTER STRING, which
// must be constructed and hold exactly one value (clauses 8.14.3, 8.17.1,
// 8.18.1 and 8.24.1). Without the TC-user's ASN.1, a context-specific or
// application tag gives no type to check. Octet-aligned and arbitrary contents
// are not checked. The TC-user's encoding rules, such as 3GPP TS 29.002 clause
// 17.1.1 for MAP, are for its own codec to apply. A dialogue PDU is TCAP
// syntax in any of the three encodings. A message parsed with WithTolerance
// marshals with TCAP's own fields encoded afresh and the TC-user's bytes as
// received.
//
// ASN.1 size and value constraints are reported as *ber.ValidationError from
// github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber; use errors.As.
// Malformed BER, including parameter and EXTERNAL single-ASN1-type bytes,
// is reported with codec errors such as ber.ErrTruncated or *ber.ElementError.
// The rules this package checks itself are reported with its Err sentinels;
// use errors.Is. Marshal wraps them in a FieldError that names the field.
// The codec reports a validly encoded element that the ASN.1 does not admit,
// and a missing mandatory component, with ber.ErrUnexpectedElement. Every
// error returned by Parse because of the data is a *ParseError, which also
// tells a stack which portion of the message failed and which transaction
// IDs were derivable, as needed for the abnormal procedures of Q.774 clauses
// 3.2.2 and 3.3.4. For a transaction-portion failure, ParseError.PAbortCause
// supplies the cause of Q.773 (06/97) Table 12; the stack applies Q.774
// (06/97) clause 3.3.4 and Table 7 to decide whether to send the Abort. An
// invalid ParseOption returns an error wrapping ErrInvalidParseOption
// instead.
//
// The codec checks that every component ID is present where required and
// lies in -128..127 (Q.773 clause 4.2.2.2). This package uses int64 for
// component IDs and local operation and error codes: values outside that
// model return ErrUnrepresentableValue. Under WithTolerance, a NULL ID where
// the model requires an integer returns ErrMissingInvokeID or ErrInvalidLinkedID.
// This package also checks dialogue versions (Q.774 clause 3.2.3): Marshal
// requires AARQ and AUDT to offer version1; both Parse modes and Marshal
// require AARE to select only version1. Received AARQ and AUDT versions are
// kept for the stack to answer.
//
// When the codec cannot decode a message, Parse inspects it for the context
// that Q.774 clauses 3.2.2 and 3.3.4 and Tables 5 and 7 need: the first
// failing dialogue portion or component, and the transaction IDs. It starts
// from the IDs the codec accepted (*wire.DecodeError.Prefix). Table 7 leaves
// it to the implementation which IDs are derivable: this package does not
// derive an OTID or DTID whose tag occurs more than once among the elements
// of the message, because an Abort sent to the wrong one could end an
// unrelated transaction at the peer. It looks for repeats within the decode
// limits, and not at all when the codec itself stopped at a limit.
// ParseError.Err is the failure of that dialogue portion or component, or
// else the codec's *wire.DecodeError.
//
// The codec decodes the dialogue-as and uniDialogue-as abstract syntaxes into
// AARQ, AARE, ABRT and AUDT; a dialogue portion in any other abstract syntax
// is an Opaque EXTERNAL. The codec requires uniDialogue-as with AUDT in a
// Unidirectional (Q.773 clause 4.2.3). This package enforces the Begin's AARQ
// requirement and the other Q.774 Table 3 rules. When Marshal encodes an AARQ,
// AARE or AUDT, a nil protocol-version is omitted and means the DEFAULT
// {version1}; a non-nil
// value is encoded, including ProtocolVersion1(). When it encodes a BIT
// STRING, it clears the unused bits of the last octet without changing the
// caller's value (X.690 (02/2021) clause 8.6.2.4).
//
// The values of TCAP protocol elements (P-Abort causes, problem codes,
// associate results and diagnostics, abort sources) are go-asn1's generated
// types, which this package names with their named numbers so that a caller
// needs no import of go-asn1. Each holds an INTEGER of any width and cannot
// be compared with ==: build one with its New function, and compare one with
// AsInt64 against the constants. BitString and ExternalEncoding are named
// here for the same reason.
//
//	cause := tcap.NewPAbortCause(tcap.PAbortCauseUnrecognizedTransactionID)
//	abort := &tcap.Abort{DTID: dtid, PAbortCause: &cause}
//
//	if c := received.PAbortCause; c != nil {
//		if v, ok := c.AsInt64(); ok && v == tcap.PAbortCauseIncorrectTransactionPortion {
//			// ...
//		}
//	}
//
// Application context names, operation codes and error codes of MAP and CAP
// are in the subpackages gsmmap and camel.
package tcap
