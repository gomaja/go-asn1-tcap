package tcap_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func TestParseDerivableIDsMatchCodecLimitLocations(t *testing.T) {
	for _, otid := range []string{"480101", "6803040101", "68800401010000", "68052403040101", "6880248004010100000000"} {
		for _, indef := range []bool{false, true} {
			text := tlv("65", otid, "490102", tlv("6c", "a106020101020101"))
			if indef {
				text = "6580" + otid + "490102" + tlv("6c", "a106020101020101") + "0000"
			}
			data := hx(text)
			for _, resource := range []string{"depth", "elements", "work"} {
				for n := 1; n <= len(data)+1; n++ {
					t.Run(fmt.Sprintf("%s/%t/%s/%d", otid, indef, resource, n), func(t *testing.T) {
						limits := ber.DecodeLimits{}
						switch resource {
						case "depth":
							limits.MaxDepth = n
						case "elements":
							limits.MaxElements = n
						case "work":
							limits.MaxWork = n
						}
						var reports ber.ViolationLog
						opts := []ber.DecodeOption{ber.WithDecodeLimits(limits), ber.WithTolerance(&reports)}
						validation := ber.ValidateBERElement(data, opts...)
						var w wire.TCMessage
						decoded := w.UnmarshalBER(data, opts...)
						if !errors.Is(validation, ber.ErrResourceLimit) {
							if errors.Is(decoded, ber.ErrResourceLimit) {
								t.Fatalf("typed-only limit: %v", decoded)
							}
							return
						}
						var vloc, dloc *ber.ElementError
						if !errors.Is(decoded, ber.ErrResourceLimit) || !errors.As(validation, &vloc) || !errors.As(decoded, &dloc) || vloc.Offset() != dloc.Offset() || !reflect.DeepEqual(vloc.ChildIndexes(), dloc.ChildIndexes()) {
							t.Fatalf("preflight %v / typed %v", validation, decoded)
						}
						_, err := tcap.Parse(data, tcap.WithDecodeLimits(limits), tcap.WithTolerance(&ber.ViolationLog{}))
						var pe *tcap.ParseError
						if !errors.As(err, &pe) || !errors.Is(err, ber.ErrResourceLimit) {
							t.Fatalf("Parse: %v", err)
						}
						cutoff := 0
						if indexes := vloc.ChildIndexes(); len(indexes) > 0 {
							cutoff = indexes[0]
						}
						var wantO, wantD string
						if cutoff > 0 {
							wantO = "01"
						}
						if cutoff > 1 {
							wantD = "02"
						}
						if pe.OTID.String() != wantO || pe.DTID.String() != wantD {
							t.Fatalf("IDs %s/%s, want %s/%s before %v at %d", pe.OTID, pe.DTID, wantO, wantD, vloc.ChildIndexes(), vloc.Offset())
						}
					})
				}
			}
		}
	}
}
