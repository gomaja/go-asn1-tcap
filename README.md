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
  v1.0.x; it moves to the main branch with the command above. The v1.0.x API
  differs (see [Migrating from v1.0.x](#migrating-from-v10x)).

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
// version 2 instead (the initiator falls back, 3GPP TS 29.002 clause 5.2).
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

`Marshal` applies the sender rules and `Parse` the receiver rules: the ASN.1
of Q.773, its encoding restrictions (clause 4.1.1: minimal lengths,
primitive strings), and the dialogue PDUs that each message type may carry
(Q.774 Table 3). Rules that depend on the transaction or dialogue state are
left to the stack built on this package.

- ASN.1 size and value constraints, such as a transaction ID of 5 octets or an
  invoke ID of 200, are `*ber.ConstraintError` (`errors.As`).
- Every other rule has an `Err` sentinel (`errors.Is`), for example
  `tcap.ErrUnexpectedDialoguePDU` or `tcap.ErrParameterNotSingleValue`.
- `Marshal` reports the offending field in a `*tcap.FieldError`.
- Every `Parse` error is a `*tcap.ParseError` that tells a TCAP stack how to
  react, as required by Q.774: the message type, the transaction IDs that
  could be derived, and the portion that failed. A failure in the transaction
  portion calls for a P-Abort (clause 3.3.4); one in the dialogue portion for
  an ABRT from the dialogue service provider (clause 3.2.2.1); one in the
  component portion for a Reject (clause 3.2.2.2), for which the error gives
  the failing component, its invoke ID when it can be derived, the dialogue,
  and the valid components that precede it.

```go
msg, err := tcap.Parse(data)
var perr *tcap.ParseError
if errors.As(err, &perr) {
    switch perr.Portion {
    case tcap.PortionTransaction:
        if perr.OTID != nil {
            // send an Abort with a P-Abort cause to perr.OTID
        }
    case tcap.PortionDialogue:
        // send an Abort with tcap.NewProviderAbortDialogue()
    case tcap.PortionComponent:
        // process perr.Components, then reject the component at perr.ComponentIndex
    }
}
```

`tcap.WithConstraintTolerance` makes `Parse` accept values outside their
ASN.1 constraints and record them in a `ber.ViolationLog`, for monitoring
traffic that does not conform. `Marshal` stays strict.

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
- `Parse` no longer falls back to a relaxed decoder, and rejects encodings
  that Q.773 forbids.
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
