package tcap_test

import (
	"encoding/hex"
	"fmt"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// A Begin with an AARQ for application context 0.4.0.0.1.0.20.3 and one
// Invoke (invoke ID 1, operation code 45).
const exampleBegin = "62374804010203046b1e281c060700118605010101a011600f80020780a1090607040000010014036c0fa10d02010102012d30050403010203"

// Parse a message and act on its type.
func ExampleParse() {
	data, _ := hex.DecodeString(exampleBegin)
	msg, err := tcap.Parse(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	switch m := msg.(type) {
	case *tcap.Begin:
		fmt.Println("Begin, OTID", m.OTID)
		if m.Dialogue != nil && m.Dialogue.Request != nil {
			fmt.Println("application context", m.Dialogue.Request.ApplicationContextName)
		}
		for _, c := range m.Components {
			if inv := c.Invoke; inv != nil {
				fmt.Printf("invoke %d, operation %v, argument %x\n", inv.InvokeID, inv.OpCode, inv.Parameter)
			}
		}
	case *tcap.Continue, *tcap.End:
		fmt.Println("dialogue continues or ends")
	case *tcap.Abort:
		fmt.Println("Abort, DTID", m.DTID)
	case *tcap.Unidirectional:
		fmt.Println("Unidirectional")
	}
	// Output:
	// Begin, OTID 01020304
	// application context 0.4.0.0.1.0.20.3
	// invoke 1, operation 45, argument 30050403010203
}

// Build a Begin that opens a dialogue with an AARQ and invokes an operation.
func ExampleBegin_Marshal() {
	begin := &tcap.Begin{
		OTID: tcap.TransactionID{0x01, 0x02, 0x03, 0x04},
		Dialogue: &tcap.Dialogue{Request: &tcap.AARQ{
			ProtocolVersion:        tcap.ProtocolVersion1(),
			ApplicationContextName: "0.4.0.0.1.0.20.3",
		}},
		Components: []tcap.Component{{Invoke: &tcap.Invoke{
			InvokeID:  1,
			OpCode:    tcap.LocalCode(45),
			Parameter: []byte{0x30, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03},
		}}},
	}
	data, err := begin.Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%x\n", data)
	// Output:
	// 62374804010203046b1e281c060700118605010101a011600f80020780a1090607040000010014036c0fa10d02010102012d30050403010203
}

// Answer a Begin with a Continue that accepts the proposed application
// context and returns a result.
func ExampleNewAcceptDialogue() {
	data, _ := hex.DecodeString(exampleBegin)
	msg, err := tcap.Parse(data)
	if err != nil {
		fmt.Println(err)
		return
	}
	begin := msg.(*tcap.Begin)
	reply := &tcap.Continue{
		OTID:     tcap.TransactionID{0x05, 0x06, 0x07, 0x08},
		DTID:     begin.OTID,
		Dialogue: tcap.NewAcceptDialogue(begin.Dialogue.Request.ApplicationContextName, nil),
		Components: []tcap.Component{{ReturnResultLast: &tcap.ReturnResult{
			InvokeID: begin.Components[0].Invoke.InvokeID,
			Result: &tcap.Result{
				OpCode:    tcap.LocalCode(45),
				Parameter: []byte{0x30, 0x04, 0x04, 0x02, 0xaa, 0xbb},
			},
		}}},
	}
	out, err := reply.Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%x\n", out)
	// Output:
	// 654a4804050607084904010203046b2a2828060700118605010101a01d611b80020780a109060704000001001403a203020100a305a1030201006c10a20e020101300902012d30040402aabb
}

// Refuse a dialogue whose application context is not supported, offering
// another one (ITU-T Q.774 (06/97) clause 3.2.1).
func ExampleNewRejectDialogue() {
	notSupported := wire.AssociateSourceDiagnosticDialogueServiceUserValueApplicationContextNameNotSupportedValue()
	refusal := &tcap.Abort{
		DTID: tcap.TransactionID{0x01, 0x02, 0x03, 0x04},
		Dialogue: tcap.NewRejectDialogue("0.4.0.0.1.0.20.2",
			tcap.ResultSourceDiagnostic{DialogueServiceUser: &notSupported}, nil),
	}
	out, err := refusal.Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%x\n", out)
	// Output:
	// 67324904010203046b2a2828060700118605010101a01d611b80020780a109060704000001001402a203020101a305a103020102
}

// Abort a transaction from the transaction sub-layer with a P-Abort cause
// (ITU-T Q.773 (06/97) Table 12).
func ExampleAbort_Marshal() {
	cause := wire.PAbortCauseUnrecognizedTransactionID
	abort := &tcap.Abort{DTID: tcap.TransactionID{0x01, 0x02, 0x03, 0x04}, PAbortCause: &cause}
	out, err := abort.Marshal()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%x\n", out)
	// Output:
	// 67094904010203044a0101
}
