# TCAP wire vectors

`corpus.json` holds 67 ITU-T TCAP messages used as the test oracle for this
package. Each vector was assembled by hand, octet by octet, from the ASN.1 of
ITU-T Q.773 (06/97) (modules TCAPMessages, DialoguePDUs and UnidialoguePDUs),
ITU-T X.880 (07/94) (Remote-Operations-Generic-ROS-PDUs) and the BER rules of
ITU-T X.690, without using this package or go-asn1. Every vector was then
decoded with Wireshark 4.6.8 (`tshark`), carried in SCCP over M3UA over SCTP so
that the TCAP dissector sees a complete stack, and the decoded fields were
compared with what the vector was built to encode.

Fields:

- `id`: stable name used by the tests.
- `valid`: whether the octets are a valid encoding of the TCAP abstract syntax.
  The negative vectors (`valid: false`) each break one rule, named in `notes`.
- `hex`: the message, lowercase hex.
- `intent`: the values the vector encodes. Transaction IDs and opaque values are
  hex, object identifiers are dotted decimal, local operation and error codes
  are integers.
- `wiresharkAgrees`: whether Wireshark decoded the same values.
- `notes`: the violated rule for a negative vector, or the reason Wireshark
  disagrees.

Wireshark disagrees on 15 vectors. Thirteen are negative vectors that Wireshark
decodes without a diagnostic. The other two are valid:

- `begin-linked-absent` encodes linkedId with the X.880 `absent` alternative
  (`81 00`). Q.773 Table 20 defines only the `[0]` Linked ID tag, which is what
  Wireshark implements, so it takes the operation code for a parameter. This
  package follows Q.773 and rejects that encoding.
- `unidirectional-audt-invoke` carries an AUDT under uniDialogue-as-id.
  Wireshark labels it a dialogue request because AARQ and AUDT share the tag
  `[APPLICATION 0]`; the fields it shows are correct.

Some vectors use forms that a canonical encoder does not produce (indefinite
lengths, a non-minimal length). They must parse to the same values as their
canonical counterparts; `Marshal` then emits the canonical form.
