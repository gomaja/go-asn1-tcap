package tcap_test

import (
	"bytes"
	"errors"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

func TestParseProfileAndRawContents(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		portion     tcap.Portion
		repaired    bool
	}{
		{"transaction nonminimal length", "620448810101", tcap.PortionTransaction, true},
		{"transaction constructed OCTET STRING", "62056803040101", tcap.PortionTransaction, true},
		{"component nonminimal length", "62114801016c0ca10a020101020101048101ff", tcap.PortionComponent, false},
		{"component constructed OCTET STRING", "62124801016c0da10b02010102010124030401ff", tcap.PortionComponent, false},
		{"user information nonminimal length", "62264801016b21281f060700118605010101a0146012a10306012abe0b280906012aa004048101ff", tcap.PortionDialogue, false},
		{"user information constructed OCTET STRING", "62274801016b222820060700118605010101a0156013a10306012abe0c280a06012aa00524030401ff", tcap.PortionDialogue, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := hx(tc.input)
			_, err := tcap.Parse(data)
			var pe *tcap.ParseError
			var validation *ber.ValidationError
			var decoded *wire.DecodeError
			// Err holds the codec's DecodeError only for a transaction failure;
			// a failing dialogue portion or component is reported alone.
			if !errors.As(err, &pe) || pe.Portion != tc.portion || !errors.As(err, &validation) || errors.As(err, &decoded) != (tc.portion == tcap.PortionTransaction) {
				t.Fatalf("strict Parse: %v", err)
			}
			var reports ber.ViolationLog
			m, err := tcap.Parse(data, tcap.WithTolerance(&reports))
			if err != nil || len(reports.Snapshot()) != 1 {
				t.Fatalf("tolerant Parse: %v; reports %v", err, reports.Snapshot())
			}
			out, err := m.Marshal()
			if tc.repaired {
				if err != nil || !bytes.Equal(out, hx("6203480101")) {
					t.Fatalf("rebuilt transaction: %x, %v", out, err)
				}
			} else if out != nil || !errors.As(err, &validation) {
				t.Fatalf("strict raw-payload Marshal: %x, %v", out, err)
			}
		})
	}
}

func TestParseOpaqueSchemaBoundaries(t *testing.T) {
	for _, input := range []string{
		// An unknown IMPLICIT parameter does not reveal its underlying string type.
		"62124801016c0da10b020101020101a0030401ff",
		// EXTERNAL octet-aligned and arbitrary contents have no BER schema here.
		"62264801016b21281f060700118605010101a0146012a10306012abe0b280906012a8104048101ff",
		"62274801016b222820060700118605010101a0156013a10306012abe0c280a06012a820500048101ff",
	} {
		m, err := tcap.Parse(hx(input))
		if err != nil {
			t.Fatal(err)
		}
		if out, err := m.Marshal(); err != nil || !bytes.Equal(out, hx(input)) {
			t.Fatalf("opaque payload changed: %x, %v", out, err)
		}
	}
}

func TestParseDecodeErrorPrefix(t *testing.T) {
	for _, input := range []string{
		"620a4801016c05a103020105",
		"650d4801014901026c05a103020105",
		// Prefix retains the leading ID before the later truncated duplicate.
		"6206480101480501",
	} {
		data := hx(input)
		var w wire.TCMessage
		codecErr := w.UnmarshalBER(data)
		var want *wire.DecodeError
		if !errors.As(codecErr, &want) || want.Prefix.Otid == nil {
			t.Fatalf("codec prefix: %v", codecErr)
		}
		_, err := tcap.Parse(data)
		var pe *tcap.ParseError
		if !errors.As(err, &pe) || !bytes.Equal(pe.OTID, *want.Prefix.Otid) {
			t.Fatalf("Parse = %v, want OTID %x", err, *want.Prefix.Otid)
		}
		// Err holds the codec's DecodeError only for a transaction failure.
		var decoded *wire.DecodeError
		if found := errors.As(err, &decoded); found != (pe.Portion == tcap.PortionTransaction) || found && decoded.Path != want.Path {
			t.Fatalf("Portion %s, error chain %v, want path %s", pe.Portion, err, want.Path)
		}
		if want.Prefix.Dtid != nil && !bytes.Equal(pe.DTID, *want.Prefix.Dtid) {
			t.Fatalf("DTID %x, want %x", pe.DTID, *want.Prefix.Dtid)
		}
		data[4] ^= 0xff
		if pe.OTID[0] != 1 {
			t.Fatal("ParseError ID aliases input")
		}
	}
}

func TestCodecOwnsComponentIDRules(t *testing.T) {
	for _, component := range []string{
		"a10a020101800200c8020101", // linked ID 200
		"a2040202ff7f",             // ReturnResult invoke ID -129
	} {
		data := hx(tlv("62", "480101", tlv("6c", component)))
		_, err := tcap.Parse(data)
		var validation *ber.ValidationError
		if !errors.As(err, &validation) {
			t.Fatalf("strict Parse: %v", err)
		}
		var reports ber.ViolationLog
		m, err := tcap.Parse(data, tcap.WithTolerance(&reports))
		if err != nil || len(reports.Snapshot()) != 1 {
			t.Fatalf("tolerant Parse: %v; %v", err, reports.Snapshot())
		}
		out, err := m.Marshal()
		if out != nil || !errors.As(err, &validation) {
			t.Fatalf("strict Marshal: %x, %v", out, err)
		}
	}
}

// Parse uses the codec's accepted IDs, including tolerated values and
// failures without a recognized message type (Q.774 (06/97) Table 7).
func TestParseAcceptedPrefixIDs(t *testing.T) {
	for _, tc := range []struct {
		name, input, otid, dtid string
		tolerant                bool
		limits                  ber.DecodeLimits
	}{
		{"unlocated missing DTID", "650a4801016c05a103020105", "01", "", false, ber.DecodeLimits{}},
		{"unknown message", "660a4801016c05a103020105", "01", "", false, ber.DecodeLimits{}},
		{"constructed ID", "620c68030401016c05a103020105", "01", "", true, ber.DecodeLimits{}},
		{"long ID", "620e480501020304056c05a103020105", "0102030405", "", true, ber.DecodeLimits{}},
		{"empty ID", "620948006c05a103020105", "", "", true, ber.DecodeLimits{}},
		{"constructed ID before limit", "65086803040101490102", "01", "", true, ber.DecodeLimits{MaxElements: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := hx(tc.input)
			var reports ber.ViolationLog
			opts := []tcap.ParseOption{tcap.WithDecodeLimits(tc.limits)}
			wireOpts := []ber.DecodeOption{ber.WithDecodeLimits(tc.limits)}
			if tc.tolerant {
				opts = append(opts, tcap.WithTolerance(&reports))
				wireOpts = append(wireOpts, ber.WithTolerance(&reports))
			}
			var w wire.TCMessage
			codecErr := w.UnmarshalBER(data, wireOpts...)
			var decoded *wire.DecodeError
			if !errors.As(codecErr, &decoded) || decoded.Prefix.Otid == nil || tcap.TransactionID(*decoded.Prefix.Otid).String() != tc.otid {
				t.Fatalf("codec accepted prefix: %v", codecErr)
			}
			_, err := tcap.Parse(data, opts...)
			var pe *tcap.ParseError
			if !errors.As(err, &pe) || pe.OTID == nil || pe.OTID.String() != tc.otid || pe.DTID.String() != tc.dtid || !bytes.Equal(pe.OTID, *decoded.Prefix.Otid) {
				t.Fatalf("missing abnormal-procedure IDs: %v", err)
			}
		})
	}
}

func TestParseUpstreamMalformedComponentPrefix(t *testing.T) {
	// Q.774 (06/97) clause 3.2.2.2/Table 5 select the first failed component.
	// A later primitive indefinite NULL must not hide that complete prefix.
	portion := "6c80a103020105a18002010602012d0580000000000000"
	for _, input := range []string{
		tlv("62", "480101", portion),
		"6280480101" + portion + "0000",
	} {
		_, err := tcap.Parse(hx(input))
		var pe *tcap.ParseError
		var decoded *wire.DecodeError
		// The codec's failure of the later component is not part of Err.
		if !errors.As(err, &pe) || errors.As(err, &decoded) || pe.Portion != tcap.PortionComponent || pe.ComponentIndex != 0 || pe.InvokeID == nil || *pe.InvokeID != 5 || pe.OTID.String() != "01" {
			t.Fatalf("first failed component: %v", err)
		}
	}
}

func TestParseInspectionKeepsTolerance(t *testing.T) {
	// The first component has a nonminimal invoke-ID length. Inspection must
	// accept it in the caller's mode before reporting the second component.
	input := tlv("62", "480101", tlv("6c", "a10702810101020101", "a103020105"))
	var reports ber.ViolationLog
	_, err := tcap.Parse(hx(input), tcap.WithTolerance(&reports))
	var pe *tcap.ParseError
	if !errors.As(err, &pe) || pe.Portion != tcap.PortionComponent || pe.ComponentIndex != 1 || len(pe.Components) != 1 || pe.Components[0].Invoke.InvokeID != 1 || pe.InvokeID == nil || *pe.InvokeID != 5 {
		t.Fatalf("tolerant inspection: %v", err)
	}
	if len(reports.Snapshot()) != 0 {
		t.Fatal("failed Parse published reports")
	}
}

func TestParseStrictTransactionFailure(t *testing.T) {
	for _, tc := range []struct{ input, otid string }{
		{"620448810101", ""},
		{"6208488101016c020000", ""},
		{"6281084801016c03a10100", "01"},
	} {
		_, err := tcap.Parse(hx(tc.input))
		var pe *tcap.ParseError
		var validation *ber.ValidationError
		if !errors.As(err, &pe) || !errors.As(err, &validation) || pe.OTID.String() != tc.otid || (pe.OTID == nil) != (tc.otid == "") || pe.Portion != tcap.PortionTransaction {
			t.Fatalf("strict transaction context: %v; %#v", err, pe)
		}
	}
}

func TestParseMalformedTransactionAfterComponent(t *testing.T) {
	for _, input := range []string{"62094801016c03a10100ff", "620b4801016c03a10100480102", "620d4801016c80a101000000ff00", "62104801016c80a103020101a10502010100ff"} {
		_, err := tcap.Parse(hx(input))
		var pe *tcap.ParseError
		if !errors.As(err, &pe) || pe.Portion != tcap.PortionTransaction || pe.ComponentIndex != -1 {
			t.Fatalf("invalid transaction layout: %v", err)
		}
	}
}

func TestParseInvokeIDInspectionKeepsMode(t *testing.T) {
	input := hx("620e4801016c09a10702810101020101")
	_, err := tcap.Parse(input)
	var pe *tcap.ParseError
	if !errors.As(err, &pe) || pe.InvokeID != nil {
		t.Fatalf("nonminimal invoke ID was derived in strict mode: %v", err)
	}
	var reports ber.ViolationLog
	if _, err := tcap.Parse(input, tcap.WithTolerance(&reports)); err != nil || len(reports.Snapshot()) != 1 {
		t.Fatalf("tolerant invoke ID: %v; %v", err, reports.Snapshot())
	}
}
