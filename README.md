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

The dialogue portion of an Abort is an AARE that refuses the dialogue or an
ABRT. The recipes fill in the values that ITU-T Q.774 (06/97) clause 3.2
prescribes:

```go
// Refuse a dialogue whose application context is not supported, and offer
// version 2 instead (the initiator falls back, 3GPP TS 29.002 V19.1.0 clause 5.2.1).
notSupported := wire.AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedValue()
refusal := &tcap.Abort{
    DTID: begin.OTID,
    Dialogue: tcap.NewRejectDialogue(gsmmap.ShortMsgGatewayContextV2,
        tcap.ResultSourceDiagnostic{DialogueServiceUser: &notSupported}, nil),
}

// TC-user abort with MAP-UserAbortInfo, and abort by the dialogue service provider.
userAbort := &tcap.Abort{DTID: peerTID, Dialogue: tcap.NewUserAbortDialogue(userInformation)}
providerAbort := &tcap.Abort{DTID: peerTID, Dialogue: tcap.NewProviderAbortDialogue()}

// Abort by the transaction sub-layer.
pAbort := &tcap.Abort{DTID: peerTID, PAbortCause: new(wire.PAbortCauseUnrecognizedTransactionID)}
```

(`wire` is `github.com/gomaja/go-asn1/telecom/ss7/tcap`, which defines the
values of TCAP protocol elements.)

### Errors and abnormal procedures

`Marshal` applies the sender rules: the ASN.1 of Q.773 and the dialogue PDUs
that each message type may carry (Q.774 Table 3). What it encodes itself uses
definite lengths, in the short form below 128 octets and otherwise in the
fewest octets as Q.773 clause 4.1.1 requires of definite lengths, and
primitive strings. Parameters are sent as given. `Parse` applies the
receiver rules: it accepts any valid BER encoding of a TCAP message and
rejects everything else, including a dialogue PDU that the message type
cannot carry. Rules that depend on the transaction or dialogue state are left
to the stack built on this package.

- ASN.1 size and value constraints, such as a transaction ID of 5 octets or an
  invoke ID of 200, are `*ber.ConstraintError` (`errors.As`).
- Malformed BER, including parameter and EXTERNAL single-ASN1-type bytes,
  returns codec errors such as `ber.ErrExtraData`, `ber.ErrTruncated`,
  `ber.ErrInvalidTag` or `*ber.ElementError`.
- TCAP rules have an `Err` sentinel (`errors.Is`), for example
  `tcap.ErrUnexpectedDialoguePDU`.
- `Marshal` reports rules checked here in a `*tcap.FieldError`. Codec errors
  retain their generated ASN.1 paths and causes, including `*ber.ConstraintError`.
- Every `Parse` error caused by the data is a `*tcap.ParseError` that tells a
  TCAP stack how to react, as required by Q.774: the message type, the
  transaction IDs that could be derived from where the message type carries
  them, and the portion that failed. A failure in the transaction portion
  calls for an Abort with a P-Abort cause to the originating transaction ID,
  when it can be derived (clause 3.3.4, Table 7: an End or an Abort is only
  discarded). One in the dialogue portion calls for an ABRT from the dialogue
  service provider (clause 3.2.2.1). One in the component portion calls for a
  Reject (clause 3.2.2.2, Table 5): the error gives the position and type of
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
        if perr.OTID != nil {
            // answer with an Abort whose DTID is perr.OTID and a P-Abort cause
        }
    case tcap.PortionDialogue:
        // answer with an Abort carrying tcap.NewProviderAbortDialogue()
    case tcap.PortionComponent:
        // process perr.Components; then, unless perr.ComponentType is
        // tcap.ComponentTypeReject, reject the component at perr.ComponentIndex
    }
}
```

`tcap.WithConstraintTolerance` makes `Parse` accept values outside their
ASN.1 constraints and record them in a `ber.ViolationLog`, for monitoring
traffic that does not conform. `Marshal` stays strict.

The codec checks Invoke IDs. This package checks linked IDs and the invoke
IDs of ReturnResult, ReturnError and Reject against −128..127 (ITU-T Q.773
(06/97) clauses 3.1 and 4.2.2.2), because the ASN.1 of Q.773 Annex A
constrains only the ID of an Invoke. `tcap.WithConstraintTolerance` makes
`Parse` accept and record out-of-range IDs of both kinds.

`OID` is a string type, so application context names can be constants.
`ParseOID` and `Marshal` validate OIDs with go-asn1, which accepts arcs of
any size; `OID.Arcs()` returns `tcap.ErrUnrepresentableValue` for an arc that
does not fit in a `uint64`. BIT STRING values are encoded as given, and the
codec rejects invalid ones. `Parse` clears the unused bits it receives
(ITU-T X.690 (02/2021) clause 8.6.2.2), so a parsed message can be
marshalled again.

When `Parse` fails on a decode limit, a transaction ID is derived only if it
and the elements before it are valid and within the limits as go-asn1 counts
them; go-asn1 locates the limit with a `ber.ElementError`. An input longer
than `MaxWork`, or a limit that go-asn1 reports without a location, yields no
IDs. A message that decoded completely keeps its IDs when the dialogue PDU
inside its EXTERNAL exceeds the limits.

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

- Invoke IDs are `int64`, checked against −128..127. `LinkedID` is now encoded
  as `[0] IMPLICIT INTEGER` and a received linked ID decodes.
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
  not `[]uint64`. `ProtocolVersion` is a `*runtime.BitString` (nil means the
  default `{version1}`; `ProtocolVersion1()` sets it explicitly).
- User information is `[]External`, not concatenated bytes.
- `NewDialogueResponseFromDialogueRequest` is `NewAcceptDialogue`.

**Errors and encoding**

- `ErrInvalidTransactionID` and `ErrInvalidInvokeID` are reported as
  `*ber.ConstraintError`; `ValidationError` is `FieldError`; `ParseError`
  carries the protocol context described above.
- `Parse` no longer falls back to a relaxed decoder: it accepts every valid
  BER encoding of a TCAP message and rejects everything else.
- `Marshal` uses definite lengths: a message received with indefinite lengths
  is re-encoded with definite lengths.
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
