package tcap_test

import (
	"encoding/hex"
	"fmt"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// A Begin whose length of 3 is sent in the long form (81 03) is valid BER but
// breaks ITU-T Q.773 (06/97) clause 4.1.1. Strict Parse refuses it;
// WithTolerance accepts it and records the violation. Neither option needs an
// import of go-asn1.
func ExampleWithTolerance() {
	data, _ := hex.DecodeString("628103480101")
	if _, err := tcap.Parse(data); err != nil {
		fmt.Println("strict: refused")
	}

	var log tcap.ViolationLog
	limits := tcap.DefaultDecodeLimits()
	limits.MaxDepth = 16
	msg, err := tcap.Parse(data, tcap.WithTolerance(&log), tcap.WithDecodeLimits(limits))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("tolerant: %T\n", msg)
	for _, v := range log.Snapshot() {
		fmt.Println(v.Kind == tcap.ProtocolRule, v.Rule.Document, v.Rule.Clause)
	}
	// Output:
	// strict: refused
	// tolerant: *tcap.Begin
	// true ITU-T Q.773 4.1.1
}
