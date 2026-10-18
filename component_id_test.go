package tcap_test

import (
	"errors"
	"fmt"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func TestLinkedIDBoundsWithTolerance(t *testing.T) {
	for _, id := range []int64{-129, -128, 127, 128} {
		value := ber.EncodeInteger(id)
		value[0] = 0x80
		data := hx(tlv("62", "480101", tlv("6c", tlv("a1", "020101", fmt.Sprintf("%x", value), "020101"))))
		_, strict := tcap.Parse(data)
		invalid := id < -128 || id > 127
		var constraint *ber.ValidationError
		if invalid != errors.As(strict, &constraint) || !invalid && strict != nil {
			t.Fatalf("%d strict: %v", id, strict)
		}
		log := &ber.ViolationLog{}
		msg, err := tcap.Parse(data, tcap.WithTolerance(log))
		if err != nil {
			t.Fatal(err)
		}
		if got := *msg.(*tcap.Begin).Components[0].Invoke.LinkedID; got != id {
			t.Fatalf("ID %d", got)
		}
		_, err = msg.Marshal()
		if invalid != errors.As(err, &constraint) || !invalid && err != nil {
			t.Fatalf("%d Marshal: %v", id, err)
		}
		wantReports := 0
		if invalid {
			wantReports = 1
		}
		if got := len(log.Snapshot()); got != wantReports {
			t.Fatalf("%d: %d reports", id, got)
		}
	}
}
