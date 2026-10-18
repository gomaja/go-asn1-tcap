package tcap_test

import (
	"bytes"
	"errors"
	"fmt"
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
						var w wire.TCMessage
						decoded := w.UnmarshalBER(data, opts...)
						var failure *wire.DecodeError
						if !errors.Is(decoded, ber.ErrResourceLimit) {
							if _, err := tcap.Parse(data, tcap.WithDecodeLimits(limits), tcap.WithTolerance(&ber.ViolationLog{})); err != nil {
								t.Fatalf("codec succeeded but Parse failed: %v", err)
							}
							return
						}
						if !errors.As(decoded, &failure) {
							t.Fatalf("codec limit without DecodeError: %v", decoded)
						}
						_, err := tcap.Parse(data, tcap.WithDecodeLimits(limits), tcap.WithTolerance(&ber.ViolationLog{}))
						var pe *tcap.ParseError
						if !errors.As(err, &pe) || !errors.Is(err, ber.ErrResourceLimit) {
							t.Fatalf("Parse: %v", err)
						}
						// Q.774 (06/97) Table 7 leaves derivability to the implementation.
						// A root failure may carry IDs accepted by the codec's probe.
						var wantO, wantD []byte
						if failure.Prefix.Otid != nil {
							wantO = *failure.Prefix.Otid
						}
						if failure.Prefix.Dtid != nil {
							wantD = *failure.Prefix.Dtid
						}
						if !bytes.Equal(pe.OTID, wantO) || !bytes.Equal(pe.DTID, wantD) || (pe.OTID == nil) != (failure.Prefix.Otid == nil) || (pe.DTID == nil) != (failure.Prefix.Dtid == nil) {
							t.Fatalf("IDs %s/%s, want codec Prefix %x/%x", pe.OTID, pe.DTID, wantO, wantD)
						}
					})
				}
			}
		}
	}
}
