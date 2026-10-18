package tcap_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
)

func TestWideOIDWireRoundTrip(t *testing.T) {
	for _, text := range []string{"1.2.18446744073709551616", "2.18446744073709551616", "2.18446744073709551615"} {
		oid, err := tcap.ParseOID(text)
		if err != nil || string(oid) != text {
			t.Fatalf("ParseOID(%s): %s, %v", text, oid, err)
		}
		m := &tcap.Begin{OTID: tcap.TransactionID{1}, Dialogue: &tcap.Dialogue{Request: &tcap.AARQ{ApplicationContextName: oid,
			UserInformation: []tcap.External{{DirectReference: oid, Encoding: runtime.ExternalOctetAligned, OctetAligned: []byte{1}}}}},
			Components: []tcap.Component{{Invoke: &tcap.Invoke{InvokeID: 1, OpCode: tcap.GlobalCode(oid)}}}}
		out, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		back, err := tcap.Parse(out)
		if err != nil || !reflect.DeepEqual(m, back) {
			t.Fatalf("wide OID round trip: %#v, %v", back, err)
		}
	}
}

func TestOIDTextConversionLimits(t *testing.T) {
	text := "2." + strings.Repeat("9", runtime.MaxOIDArcDigits+1)
	if got, err := tcap.ParseOID(text); got != "" || !errors.Is(err, runtime.ErrOIDTextLimit) || errors.Is(err, tcap.ErrUnrepresentableValue) {
		t.Fatalf("ParseOID resource limit: %q, %v", got, err)
	}
	if got, err := tcap.OID(text).Arcs(); got != nil || !errors.Is(err, runtime.ErrOIDTextLimit) {
		t.Fatalf("Arcs resource limit: %v, %v", got, err)
	}
	arcs := make([]uint64, runtime.MaxOIDArcs+1)
	if got, err := tcap.OIDFromArcs(arcs...); got != "" || !errors.Is(err, runtime.ErrOIDTextLimit) {
		t.Fatalf("OIDFromArcs resource limit: %q, %v", got, err)
	}
}
