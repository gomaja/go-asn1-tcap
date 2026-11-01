# go-asn1-tcap

Encode and decode ITU-T TCAP (Transaction Capabilities Application Part)
messages in Go, built on the generated BER codec of
[go-asn1](https://github.com/gomaja/go-asn1).

[![Go Reference](https://pkg.go.dev/badge/github.com/gomaja/go-asn1-tcap.svg)](https://pkg.go.dev/github.com/gomaja/go-asn1-tcap)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

TCAP carries the operations of MAP, CAP, INAP and other SS7 and SIGTRAN
applications. This package covers the complete message format of
ITU-T Q.773 (06/97):

- the five message types: Begin, Continue, End, Abort and Unidirectional;
- the components: Invoke (with linked ID), Return Result (Last and Not
  Last), Return Error and Reject, with local and global operation and error
  codes;
- the dialogue portion: the structured dialogue PDUs AARQ, AARE and ABRT, the
  unstructured dialogue PDU AUDT, and dialogue portions in any other abstract
  syntax, with their user information as EXTERNAL values.

## Install

Depend on the main branch:

```bash
go get github.com/gomaja/go-asn1-tcap@main
```

The main branch is the only supported version. It follows the main branch of
go-asn1, and keeps no backward-compatible aliases or wrappers: when something
changes, there is one way to do it.

The module was tagged v1.0.0 and v1.0.1 before it moved to the main branch.
Those tags and their GitHub releases are deleted, and v1.0.2 was published
only to retract all three (see the `retract` block in `go.mod`). What that
means for a consumer:

- proxy.golang.org and sum.golang.org keep v1.0.0–v1.0.2 permanently; a
  deleted tag cannot be removed from them. Because they are retracted, the go
  command does not offer them: `go get github.com/gomaja/go-asn1-tcap` with
  no version, `@latest` and `go list -m -u` resolve to the main branch.
- Without tags, a version of the main branch is a pseudo-version
  `v0.0.0-<UTC time>-<commit>`, which sorts below v1.0.x. Minimal version
  selection compares by version: if any module in your build still requires
  v1.0.x, that retracted release wins over the main branch, and `go build`
  and `go mod tidy` say nothing about it. `go get` warns that the selected
  version is retracted and `go list -m -u all` marks it `(retracted)`; update
  the module that requires it.
- A project that requires v1.0.x is warned that it is retracted. `go get -u`
  leaves it there, because the main branch's pseudo-versions sort below
  v1.0.x. v1.0.x also required go-asn1 v0.3.0, which sorts above the main
  branch of go-asn1 in the same way and does not build with this package, so
  move both modules to their main branches together:

  ```bash
  go get github.com/gomaja/go-asn1-tcap@main github.com/gomaja/go-asn1@main
  ```

  The v1.0.x API differs (see [Migrating from v1.0.x](#migrating-from-v10x)).

## Usage

### Parse

```go
import (
    tcap "github.com/gomaja/go-asn1-tcap"
    "github.com/gomaja/go-asn1-tcap/gsmmap"
)

msg, err := tcap.Parse(data)
if err != nil {
    return err
}
switch m := msg.(type) {
case *tcap.Begin:
    if m.Dialogue != nil && m.Dialogue.Request != nil {
        fmt.Println("application context", m.Dialogue.Request.ApplicationContextName)
    }
    for _, c := range m.Components {
        if c.Invoke != nil && c.Invoke.OpCode == gsmmap.OpCodeSendRoutingInfoForSM {
            // c.Invoke.Parameter is the BER encoding of RoutingInfoForSM-Arg
        }
    }
case *tcap.Continue, *tcap.End, *tcap.Abort, *tcap.Unidirectional:
    // ...
}
```

`Parse` returns a `*tcap.Begin`, `*tcap.Continue`, `*tcap.End`,
`*tcap.Abort` or `*tcap.Unidirectional`. The result never aliases `data`.

### Build and marshal

Messages are plain structs:

```go
begin := &tcap.Begin{
    OTID: tcap.TransactionID{0x00, 0x47, 0x34, 0xa8},
    Dialogue: &tcap.Dialogue{
        Request: &tcap.AARQ{
            ProtocolVersion:        tcap.ProtocolVersion1(),
            ApplicationContextName: gsmmap.ShortMsgGatewayContextV3,
        },
    },
    Components: []tcap.Component{{
        Invoke: &tcap.Invoke{
            InvokeID:  1,
            OpCode:    gsmmap.OpCodeSendRoutingInfoForSM,
            Parameter: argument, // complete BER encoding of one value
        },
    }},
}
data, err := begin.Marshal()
```

Answer it with a Continue that accepts the dialogue, then end the transaction
with a result:

```go
reply := &tcap.Continue{
    OTID:     localTID,
    DTID:     begin.OTID,
    Dialogue: tcap.NewAcceptDialogue(gsmmap.ShortMsgGatewayContextV3, nil),
}

end := &tcap.End{
    DTID: peerTID,
    Components: []tcap.Component{{
        ReturnResultLast: &tcap.ReturnResult{
            InvokeID: 1,
            Result: &tcap.Result{
                OpCode:    gsmmap.OpCodeSendRoutingInfoForSM,
                Parameter: result, // complete BER encoding of one value
            },
        },
    }},
}
```

A Return Error carries an error code, local or global, and an optional
parameter:

```go
tcap.Component{ReturnError: &tcap.ReturnError{
    InvokeID:  1,
    ErrorCode: gsmmap.ErrorCodeUnknownSubscriber,
}}
```

### Abort

The dialogue portion of an Abort is an AARE with result reject-permanent,
an ABRT, or user information in another abstract syntax. The recipes fill in
the values that ITU-T Q.774 (06/97) clause 3.2 prescribes:

```go
// Refuse a dialogue whose application context is not supported, and offer
// version 2 instead (the initiator falls back, 3GPP TS 29.002 V19.1.0 clause 5.2.1).
notSupported := tcap.NewDialogueServiceUserDiagnostic(tcap.DialogueServiceUserApplicationContextNameNotSupported)
refusal := &tcap.Abort{
    DTID: begin.OTID,
    Dialogue: tcap.NewRejectDialogue(gsmmap.ShortMsgGatewayContextV2,
        tcap.ResultSourceDiagnostic{DialogueServiceUser: &notSupported}, nil),
}

// TC-user abort with MAP-UserAbortInfo, and abort by the dialogue service provider.
userAbort := &tcap.Abort{DTID: peerTID, Dialogue: tcap.NewUserAbortDialogue(userInformation)}
providerAbort := &tcap.Abort{DTID: peerTID, Dialogue: tcap.NewProviderAbortDialogue()}

// Abort by the transaction sub-layer.
cause := tcap.NewPAbortCause(tcap.PAbortCauseUnrecognizedTransactionID)
pAbort := &tcap.Abort{DTID: peerTID, PAbortCause: &cause}
```

P-Abort causes, problem codes, dialogue results and diagnostics, and abort
sources hold INTEGERs of any width, so they cannot be compared with `==`.
Compare a received one with `AsInt64` against the constants:

```go
// The responder does not support the proposed application context; the
// AARE names the one it offers instead (Q.774 clause 3.2.1).
if d := received.Dialogue; d != nil && d.Response != nil {
    if u := d.Response.ResultSourceDiagnostic.DialogueServiceUser; u != nil {
        if v, ok := u.AsInt64(); ok && v == tcap.DialogueServiceUserApplicationContextNameNotSupported {
            retry(d.Response.ApplicationContextName)
        }
    }
}
```

### Errors and abnormal procedures

`Marshal` applies the sender rules. The go-asn1 codec checks the ASN.1 of
Q.773 Annex A and X.880, the encoding rules of X.680 and X.690, and Q.773
clauses 4.1.1, 4.2.2.2 and 4.2.3. This package checks the dialogue PDUs
and results that each message type may carry (Q.774 Table 3), the dialogue
versions (clause 3.2.3), and whether values fit its Go model. TCAP's own
fields use definite lengths, in the short form below 128 octets and otherwise
in the fewest octets, and primitive strings (Q.773 clause 4.1.1). Parameters
retain their supplied bytes and are checked only for well-formed BER.

`Parse` applies the receiver rules. By default it accepts BER with the
restrictions of Q.773 clause 4.1.1 in TCAP's own syntax: lengths below 128
octets in the short form, long-form lengths in the fewest octets, and OCTET
STRING and BIT STRING values in primitive form. Indefinite lengths of
constructed values are accepted. `WithTolerance` also accepts other valid BER
encodings and values outside ASN.1 constraints, and records each violation
when parsing succeeds. This package applies the dialogue rules of ITU-T Q.774
(06/97) Table 3 itself, in both `Parse` modes and in `Marshal`:

- a Begin carries an AARQ (Figure A.5, sheet 3);
- a Continue or an End carries an AARE with result accepted (Figure A.5,
  sheet 7) or user information in another abstract syntax (clause 3.2.1.2);
- an Abort carries an ABRT, an AARE with result reject-permanent (Table 3,
  Note 3; clauses 3.2.1.2 and 3.2.3), or user information in another
  abstract syntax (Q.773 clause 3.1).

A misplaced dialogue PDU, including user information in a Begin, is
`tcap.ErrUnexpectedDialoguePDU`; an AARE with any other result is
`tcap.ErrUnexpectedDialogueResult`. The codec requires the AUDT in a
Unidirectional and keeps its abstract syntax out of the other messages
(Q.773 clause 4.2.3); under `WithTolerance`, `Parse` accepts a Unidirectional
carrying another abstract syntax and records the violation, and `Marshal`
refuses it. Rules that depend on transaction or dialogue state, such as
whether a Continue or an End may still carry its AARE, are left to the stack.

The codec's errors are go-asn1's types and sentinels. To match them with
`errors.As` or `errors.Is`, import
`github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber` (`ber` below) or
`github.com/gomaja/go-asn1/telecom/ss7/tcap` (`wire`).

- ASN.1 size and value constraints, such as a transaction ID of 5 octets or an
  invoke ID of 200, are `*ber.ValidationError` (`errors.As`).
- Malformed BER, including parameter and EXTERNAL single-ASN1-type bytes,
  returns codec errors such as `ber.ErrExtraData`, `ber.ErrTruncated`,
  `ber.ErrInvalidTag` or `*ber.ElementError`.
- The codec reports a validly encoded element that the ASN.1 does not admit,
  such as one with an unexpected tag, and a missing mandatory component with
  `ber.ErrUnexpectedElement`.
- The rules this package checks itself have an `Err` sentinel (`errors.Is`),
  for example `tcap.ErrUnrecognizedComponent` or
  `tcap.ErrUnexpectedDialoguePDU`.
- `Marshal` reports rules checked here in a `*tcap.FieldError`. Codec errors
  retain their generated ASN.1 paths and causes, including `*ber.ValidationError`.
- When the codec cannot decode a message, its error is a `*wire.DecodeError`
  with an ASN.1 path, the transaction IDs accepted under the active options,
  and the cause. `errors.As` reaches it through `*tcap.ParseError`, unless `Parse`
  locates the failing dialogue portion or component itself; the error then
  describes that element alone.
- Every `Parse` error caused by the data is a `*tcap.ParseError` that tells a
  TCAP stack how to react, as required by Q.774: the message type, the
  transaction IDs derivable under this package's Table 7 policy, and the
  portion that failed. A failure in the transaction portion calls for an
  Abort to the originating transaction ID, when it can be derived, with the
  P-Abort cause that `perr.PAbortCause()` returns (clause 3.3.4, Table 7: a
  Unidirectional, End or Abort is never answered with an Abort). One in the
  dialogue portion calls for an ABRT from the dialogue service provider
  (clause 3.2.2.1). One in the component portion calls for a Reject (clause
  3.2.2.2, Table 5): the error gives the position and type of
  the failing component, its invoke ID when it can be derived, the dialogue,
  and the valid components that precede it. A malformed Reject is discarded,
  not rejected.
- An invalid `ParseOption` returns an error wrapping
  `tcap.ErrInvalidParseOption`, not a `*tcap.ParseError`.

```go
msg, err := tcap.Parse(data)
var perr *tcap.ParseError
if errors.As(err, &perr) {
    switch perr.Portion {
    case tcap.PortionTransaction:
        if cause, ok := perr.PAbortCause(); ok && perr.OTID != nil {
            reply(&tcap.Abort{DTID: perr.OTID, PAbortCause: &cause})
        }
    case tcap.PortionDialogue:
        // answer with an Abort carrying tcap.NewProviderAbortDialogue()
    case tcap.PortionComponent:
        // process perr.Components; then, unless perr.ComponentType is
        // tcap.ComponentTypeReject, reject the component at perr.ComponentIndex
    }
}
```

`tcap.WithTolerance` requires a non-nil `*tcap.ViolationLog`, whose
`Snapshot` returns `tcap.Violation` records; `tcap.WithDecodeLimits` takes a
`tcap.DecodeLimits`, starting from `tcap.DefaultDecodeLimits()`. These are
go-asn1's own types, so no import of go-asn1 is needed. Reports are published
only when `Parse` succeeds. `Marshal` takes no options and encodes strictly.

The codec checks that every component ID is present where required and lies
in −128..127 (Q.773 clause 4.2.2.2). This package uses `int64` for component
IDs and local operation and error codes. Values outside that model return
`tcap.ErrUnrepresentableValue`. Under `WithTolerance`, a NULL ID where this
model requires an integer returns `tcap.ErrMissingInvokeID` or
`tcap.ErrInvalidLinkedID`. For dialogue versions (Q.774 clause 3.2.3),
`Marshal` requires an AARQ or AUDT to offer version1, and both Parse modes
and `Marshal` require an AARE to select only version1. Received AARQ and
AUDT versions are kept for the stack to answer.

The codec decodes the dialogue-as and uniDialogue-as abstract syntaxes into
AARQ, AARE, ABRT and AUDT; a dialogue portion in any other abstract syntax is
an `Opaque` EXTERNAL. The codec requires uniDialogue-as with AUDT in a
Unidirectional (Q.773 clause 4.2.3). This package enforces the Begin's AARQ
requirement (Q.774 Figure A.5, sheet 3) and Table 3 placement and results in
both modes. When `Marshal` encodes an AARQ, AARE or AUDT, a nil
protocol-version is omitted and means the DEFAULT `{version1}`; a non-nil value is encoded,
including `ProtocolVersion1()` as `80 02 07 80` (X.690 (02/2021) clause 8.9.3).
When it encodes a BIT STRING, it clears the unused bits of the last octet
without changing the caller's value (clause 8.6.2.4); an invalid bit length
is rejected.

TCAP's own syntax is the TC message, the component and dialogue syntax, and
the encoding headers of an EXTERNAL. Parameters and the data values of user
information and Opaque EXTERNALs are the TC-user's syntax (ITU-T X.690
(02/2021) clauses 8.15 and 8.18), which Q.773 clause 4.1.1 does not cover.
Parameters and single-ASN1-type contents keep the BER bytes they were given
or received; `Parse` in either mode and `Marshal` check only that they are
well-formed BER. That covers REAL contents (X.690 clause 8.5) and the explicit
[0] of an EXTERNAL, EMBEDDED PDV or CHARACTER STRING, which must be constructed
and hold exactly one value (clauses 8.14.3, 8.17.1, 8.18.1 and 8.24.1). Without
the TC-user's ASN.1, a context-specific or application tag gives no type to
check. Octet-aligned and arbitrary contents are not checked. The TC-user's
encoding rules, such as 3GPP TS 29.002 clause 17.1.1 for MAP, are for its own
codec to apply. A dialogue PDU is TCAP syntax in any of the three encodings. A
message parsed with `WithTolerance` marshals with TCAP's own fields encoded
afresh and the TC-user's bytes as received.

`OID` is a string type, so application context names can be constants.
`ParseOID` and `Marshal` validate OIDs with go-asn1, which accepts arcs of
any size; `OID.Arcs()` returns `tcap.ErrUnrepresentableValue` for an arc that
does not fit in a `uint64`.

Decode limits apply to decoding and to the inspection that follows a failure.
On a codec failure, `Parse` copies transaction IDs from
`wire.DecodeError.Prefix`: the IDs the decoder accepted under the active
options. Q.774 Table 7 leaves it to the implementation which IDs are
derivable: this package does not derive an OTID or DTID whose tag occurs more
than once among the elements of the message, because an Abort sent to the
wrong one could end an unrelated transaction at the peer. It looks for
repeats within the decode limits, and not when the codec itself stopped at a
limit. An empty ID accepted with `WithTolerance` is non-nil.

### Subpackages

| Package | Contents |
|---|---|
| `gsmmap` | MAP application context names, operation codes, error codes and dialogue abstract syntax (3GPP TS 29.002) |
| `camel` | CAP application context names, operation codes, error codes and dialogue abstract syntaxes (3GPP TS 29.078, GSM 09.78) |

## Standards

- ITU-T Q.773 (06/97) Transaction capabilities formats and encoding
- ITU-T Q.774 (06/97) Transaction capabilities procedures
- ITU-T X.880 (07/94) Remote Operations, with Corrigendum 1 and Amendment 1
- ITU-T X.690 (02/2021) BER, with Erratum 1
- 3GPP TS 29.002 V19.1.0 (MAP) and TS 29.078 V19.0.0 (CAP)

## Migrating from v1.0.x

**Messages**

- `TCAP` is `Message`, and `BeginTCAP`, `ContinueTCAP`, `EndTCAP`,
  `AbortTCAP` and `UnidirectionalTCAP` are `Begin`, `Continue`, `End`,
  `Abort` and `Unidirectional`. `MessageType()` is gone: use a type switch.
  `Otid` and `Dtid` are `OTID` and `DTID`.
- `NewBegin`, `NewContinue`, `NewEnd` and their `With*` options are gone:
  build messages as struct literals. `NewAcceptDialogue`,
  `NewRejectDialogue`, `NewUserAbortDialogue` and `NewProviderAbortDialogue`
  build dialogue portions.
- `AbortTCAP.UAbortCause []byte` is `Abort.Dialogue`, a decoded AARE, ABRT or
  opaque EXTERNAL.

**Components**

- Invoke IDs are `int64`; the codec checks them against −128..127.
  `LinkedID` is encoded as `[0] IMPLICIT INTEGER` and a received linked ID
  decodes.
- Operation and error codes are `Code` values: `LocalCode(n)` or
  `GlobalCode(oid)`.
- `ReturnResult.OpCode` and `Parameter` moved into `ReturnResult.Result`.
- `Reject` has a `Problem` with exactly one alternative; there is no default
  problem.
- A parameter is the complete BER encoding of one value. Several values are no
  longer wrapped in a SEQUENCE automatically.

**Dialogue**

- `Dialogue.Request`, `Response` and `Abort` are `*AARQ`, `*AARE` and
  `*ABRT`; `Unidirectional` (`*AUDT`) and `Opaque` are new. `DialogAsId` is
  gone: the abstract syntax follows from the PDU.
- Application context names are `OID` strings such as `"0.4.0.0.1.0.20.3"`,
  not `[]uint64`. `ProtocolVersion` is a `*BitString`, go-asn1's BIT STRING
  named in this package. Nil means the default `{version1}` and omits the
  field. `ProtocolVersion1()` returns an explicit value, which `Marshal`
  encodes in an AARQ, AARE or AUDT.
- User information is `[]External`, not concatenated bytes.
- `NewDialogueResponseFromDialogueRequest` is `NewAcceptDialogue`.

**Errors and encoding**

- `ErrInvalidTransactionID` and `ErrInvalidInvokeID` are reported as
  `*ber.ValidationError` from the TCAP runtime. The old package type
  `ValidationError` is `FieldError`; `ParseError` carries the protocol
  context described above.
- Strict `Parse` accepts the Q.773 clause 4.1.1 BER profile in TCAP's own
  syntax. `WithTolerance` also accepts other valid BER encodings and values
  outside ASN.1 constraints, and records each violation when parsing
  succeeds. Both modes enforce the dialogue rules of Q.774 Table 3, which
  this package applies.
- `Marshal` uses definite lengths for transaction and dialogue fields.
  Parameters and EXTERNAL single-ASN1-type contents retain their BER bytes
  and are checked only for well-formed BER.
- `MinTransactionIDLength`, `MaxTransactionIDLength`, `MinInvokeID`,
  `MaxInvokeID`, `DefaultProtocolVersion` and `DefaultAcnPrefix` are gone.

**Subpackages**

- `gsmmap` and `camel` application context names are complete `tcap.OID`
  constants per context and version; the context and version numbers are
  gone. The old `camel` values produced wrong CAP object identifiers.
- `gsmmap` operation codes are `tcap.LocalCode` values limited to TS 29.002;
  the TS 24.080 supplementary-service operations and the withdrawn MAPsec
  operations are gone.

## License

MIT; see [LICENSE](LICENSE).
