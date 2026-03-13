# go-asn1-tcap

An ergonomic Go wrapper for TCAP (Transaction Capabilities Application Part) built on top of [go-asn1](https://github.com/gomaja/go-asn1) auto-generated ASN.1 types.

[![Go Reference](https://pkg.go.dev/badge/github.com/gomaja/go-asn1-tcap.svg)](https://pkg.go.dev/github.com/gomaja/go-asn1-tcap)
[![Go Report Card](https://goreportcard.com/badge/github.com/gomaja/go-asn1-tcap)](https://goreportcard.com/report/github.com/gomaja/go-asn1-tcap)
[![Go Version](https://img.shields.io/github/go-mod/go-version/gomaja/go-asn1-tcap)](https://github.com/gomaja/go-asn1-tcap/blob/main/go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Package tcap provides handling of TCAP (Transaction Capabilities Application Part) in the SS7/SIGTRAN protocol stack, based on ITU-T Q.773 (06/97).

TCAP is used in telecommunications networks for SS7-SIGTRAN information exchange between applications — commonly for SMS delivery, subscriber information retrieval, and authentication in mobile networks.

This library uses the auto-generated BER-encoded ASN.1 types from [go-asn1](https://github.com/gomaja/go-asn1) for spec-accurate encoding/decoding, wrapped in an idiomatic Go API with builder patterns, validation, and flat component slices.

### Relationship to go-tcap

This library is a reimplementation of [go-tcap](https://github.com/gomaja/go-tcap) with a different internal architecture:

| Aspect | go-tcap | go-asn1-tcap |
|--------|---------|-------------|
| ASN.1 model | Hand-written structs using `encoding/asn1` | Auto-generated types from [go-asn1](https://github.com/gomaja/go-asn1) |
| Encoding | DER only (needs `go-asn1utils` for BER) | Native BER/DER support |
| Components | Recursive linked list | Flat `[]Component` slice |
| Optional fields | Magic value `255` for omission | Pointer types (`*T`) |
| Operation codes | `uint8` (local only) | `int64` (wider range) |

## Installation

```bash
go get github.com/gomaja/go-asn1-tcap
```

## Quick Start

### Parsing TCAP Messages

```go
import tcap "github.com/gomaja/go-asn1-tcap"

// Parse BER-encoded TCAP bytes
msg, err := tcap.Parse(berBytes)
if err != nil {
    log.Fatal(err)
}

switch msg.MessageType() {
case tcap.MessageTypeBegin:
    begin := msg.(*tcap.BeginTCAP)
    fmt.Printf("Begin OTID: %x\n", begin.Otid)
    for _, comp := range begin.Components {
        if comp.Invoke != nil {
            fmt.Printf("Invoke OpCode: %d\n", comp.Invoke.OpCode)
        }
    }
case tcap.MessageTypeEnd:
    end := msg.(*tcap.EndTCAP)
    fmt.Printf("End DTID: %x\n", end.Dtid)
}
```

### Building TCAP Messages

```go
// Create a Begin message with dialogue and invoke component
msg, err := tcap.NewBegin(
    []byte{0x00, 0x47, 0x34, 0xa8}, // Originating Transaction ID
    tcap.WithBeginDialogueRequest(20, 3), // ACN: shortMsgGateway v3
    tcap.WithBeginInvoke(0, 45, payload), // InvokeID=0, OpCode=45 (SRI-SM)
)
if err != nil {
    log.Fatal(err)
}

// Marshal to BER bytes
bytes, err := msg.Marshal()
```

### Creating Response Messages

```go
// Create an End message with dialogue response
msg, err := tcap.NewEnd(
    dtid,
    tcap.WithEndDialogueResponse(20, 3),
    tcap.WithEndReturnResultLast(0, &opCode, resultPayload),
)
```

### Creating Continue Messages

```go
// Create a Continue message
msg, err := tcap.NewContinue(
    otid, dtid,
    tcap.WithContinueDialogueResponse(25, 3),
    tcap.WithContinueInvoke(1, 44, payload),
)
```

## Features

### Transaction Portion

| Message Type   | Parse | Marshal |
|----------------|-------|---------|
| Unidirectional | Yes   | Yes     |
| Begin          | Yes   | Yes     |
| End            | Yes   | Yes     |
| Continue       | Yes   | Yes     |
| Abort          | Yes   | Yes     |

### Component Portion

| Component Type           | Parse | Marshal |
|--------------------------|-------|---------|
| Invoke                   | Yes   | Yes     |
| Return Result (Last)     | Yes   | Yes     |
| Return Result (Not Last) | Yes   | Yes     |
| Return Error             | Yes   | Yes     |
| Reject                   | Yes   | Yes     |

### Dialogue Portion

| Dialogue Type                       | Parse | Marshal |
|-------------------------------------|-------|---------|
| Dialogue Request (AARQ-apdu)        | Yes   | Yes     |
| Dialogue Response (AARE-apdu)       | Yes   | Yes     |
| Dialogue Abort (ABRT-apdu)          | Yes   | Yes     |
| Unidirectional Dialogue (AUDT-apdu) | Yes   | Yes     |

## API Documentation

### Main Types

- `TCAP` — Interface representing any TCAP message (implements `Marshal()` and `MessageType()`)
- `BeginTCAP`, `EndTCAP`, `ContinueTCAP`, `AbortTCAP`, `UnidirectionalTCAP` — Message types
- `Component` — CHOICE struct with `Invoke`, `ReturnResultLast`, `ReturnResultNotLast`, `ReturnError`, `Reject`
- `Dialogue` — Dialogue portion with `Request`, `Response`, `Abort` fields

### Constructors

- `NewBegin(otid, ...BeginOption)` — Create a Begin message
- `NewEnd(dtid, ...EndOption)` — Create an End message
- `NewContinue(otid, dtid, ...ContinueOption)` — Create a Continue message

### Functional Options

**Begin**: `WithBeginDialogueRequest`, `WithBeginDialogueObject`, `WithBeginInvoke`

**End**: `WithEndDialogueResponse`, `WithEndDialogueObject`, `WithEndReturnResultLast`, `WithEndReturnError`

**Continue**: `WithContinueDialogueRequest`, `WithContinueDialogueResponse`, `WithContinueDialogueObject`, `WithContinueInvoke`, `WithContinueReturnResultLast`

## Common Use Cases

This library can be used to implement SS7/SIGTRAN protocols that use TCAP:

- **MAP** (Mobile Application Part) — SMS routing, subscriber queries
- **CAP** (CAMEL Application Part) — Intelligent network services
- **INAP** (Intelligent Network Application Part) — Call handling

## Author

Marwan Jadid

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/gomaja/go-asn1-tcap/blob/main/LICENSE) file for details.
