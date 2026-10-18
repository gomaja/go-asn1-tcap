package tcap_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
)

// ITU-T Q.774 (06/97) Table 3 and Figure A.5 (sheets 3 and 7).
func TestProcedureDialoguePlacementVectors(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"Begin AARE", "62354801016b262824060700118605010101a0196117a109060704000001001303a203020100a305a1030201006c08a106020105020102"},
		{"Begin ABRT", "62214801016b122810060700118605010101a00564038001006c08a106020105020102"},
		{"Continue ABRT", "65244801014901026b122810060700118605010101a00564038001006c08a106020105020102"},
		{"End ABRT", "64214901026b122810060700118605010101a00564038001006c08a106020105020102"},
		{"Begin Opaque", tlv("62", hexOTID, tlv("6b", hexOpaqueExt))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tolerant := range []bool{false, true} {
				var reports ber.ViolationLog
				var opts []tcap.ParseOption
				if tolerant {
					opts = append(opts, tcap.WithTolerance(&reports))
				}
				m, err := tcap.Parse(hx(tc.input), opts...)
				var pe *tcap.ParseError
				if m != nil || !errors.Is(err, tcap.ErrUnexpectedDialoguePDU) || !errors.As(err, &pe) || pe.Portion != tcap.PortionDialogue || pe.ComponentIndex != -1 || pe.Components != nil || len(reports.Snapshot()) != 0 {
					t.Fatalf("tolerant %t: %v, %v, reports %v", tolerant, m, err, reports.Snapshot())
				}
			}
		})
	}
}

// ITU-T Q.774 (06/97) Table 3 Note 3 and clauses 3.2.1.2 and 3.2.3
// permit only accepted (0) and reject-permanent (1), never result 2.
func TestProcedureUndefinedDialogueResult(t *testing.T) {
	// An AARE with result 2 is refused where an AARE may appear; where it may
	// not, the misplaced PDU is reported first.
	dp := dialoguePortion(hexDialogueAS, strings.Replace(hexAAREAcc, "a203020100", "a203020102", 1))
	for _, tc := range []struct {
		input string
		want  error
	}{
		{tlv("65", hexOTID, hexDTID, dp), tcap.ErrUnexpectedDialogueResult},
		{tlv("64", hexDTID, dp), tcap.ErrUnexpectedDialogueResult},
		{tlv("67", hexDTID, dp), tcap.ErrUnexpectedDialogueResult},
		{tlv("62", hexOTID, dp), tcap.ErrUnexpectedDialoguePDU},
		{tlv("61", dp, tlv("6c", hexInvoke)), tcap.ErrUnexpectedDialoguePDU},
	} {
		t.Run(tc.input[:2]+"/Parse", func(t *testing.T) {
			for _, tolerant := range []bool{false, true} {
				var reports ber.ViolationLog
				var opts []tcap.ParseOption
				if tolerant {
					opts = append(opts, tcap.WithTolerance(&reports))
				}
				m, err := tcap.Parse(hx(tc.input), opts...)
				var pe *tcap.ParseError
				if m != nil || !errors.Is(err, tc.want) || !errors.As(err, &pe) || pe.Portion != tcap.PortionDialogue || len(reports.Snapshot()) != 0 {
					t.Fatalf("%s, tolerant %t: %v, %v", tc.input, tolerant, m, err)
				}
			}
		})
	}
	d := aareD(pv1(), false)
	d.Response.Result = wire.NewAssociateResultInt64(2)
	for _, tc := range []struct {
		m    tcap.Message
		want error
		path string
	}{
		{&tcap.Continue{OTID: tidO, DTID: tidD, Dialogue: d}, tcap.ErrUnexpectedDialogueResult, "Dialogue.Response.Result"},
		{&tcap.End{DTID: tidD, Dialogue: d}, tcap.ErrUnexpectedDialogueResult, "Dialogue.Response.Result"},
		{&tcap.Abort{DTID: tidD, Dialogue: d}, tcap.ErrUnexpectedDialogueResult, "Dialogue.Response.Result"},
		{&tcap.Begin{OTID: tidO, Dialogue: d}, tcap.ErrUnexpectedDialoguePDU, "Dialogue"},
		{&tcap.Unidirectional{Dialogue: d, Components: []tcap.Component{invokeC(1)}}, tcap.ErrUnexpectedDialoguePDU, "Dialogue"},
	} {
		t.Run(fmt.Sprintf("%T/Marshal", tc.m), func(t *testing.T) {
			out, err := tc.m.Marshal()
			var fe *tcap.FieldError
			if out != nil || !errors.Is(err, tc.want) || !errors.As(err, &fe) || fe.Path != tc.path {
				t.Fatalf("%T: %x, %v", tc.m, out, err)
			}
		})
	}
}

// ITU-T Q.774 (06/97) Table 7 leaves derivability to the implementation.
// A repeated immediate ID tag is ambiguous, including a malformed last child.
func TestProcedureRepeatedTransactionIDs(t *testing.T) {
	for _, tc := range []struct{ name, input, otid, dtid string }{
		{"both repeated", tlv("65", "480101", "490102", "480103", "490104"), "", ""},
		{"constructed duplicate", tlv("62", "480101", "6803040102"), "", ""},
		{"malformed duplicate tag only", tlv("62", "480101", "48"), "", ""},
		{"empty duplicated ID", tlv("62", "4800", "4800"), "", ""},
		{"duplicate after five children", tlv("62", "480101", "4f00", "4e00", "4d00", "4a00", "480102"), "", ""},
		{"indefinite outer duplicate", "62804801014801020000", "", ""},
		{"truncated outer duplicate", "620a480101480102", "", ""},
		{"header profile violation", "628106480101480102", "", ""},
		{"nested ID tag", tlv("62", "480101", tlv("4f", "480102")), "01", ""},
		{"different class", tlv("62", "480101", "880102"), "01", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tolerant := range []bool{false, true} {
				var opts []tcap.ParseOption
				if tolerant {
					opts = append(opts, tcap.WithTolerance(&ber.ViolationLog{}))
				}
				pe := reviewFailure(t, tc.input, opts...)
				if pe.OTID.String() != tc.otid || pe.DTID.String() != tc.dtid || tc.otid == "" && pe.OTID != nil || tc.dtid == "" && pe.DTID != nil {
					t.Fatalf("tolerant %t: IDs %s/%s, want %s/%s", tolerant, pe.OTID, pe.DTID, tc.otid, tc.dtid)
				}
			}
		})
	}
}

func TestProcedureCodecLimitKeepsRepeatedPrefix(t *testing.T) {
	data := hx(tlv("65", "480101", "490102", "480103", "490104"))
	for _, tolerant := range []bool{false, true} {
		for _, limits := range []ber.DecodeLimits{{MaxElements: 2}, {MaxElements: 3}, {MaxWork: 1}} {
			opts := []ber.DecodeOption{ber.WithDecodeLimits(limits)}
			parseOpts := []tcap.ParseOption{tcap.WithDecodeLimits(limits)}
			if tolerant {
				opts = append(opts, ber.WithTolerance(&ber.ViolationLog{}))
				parseOpts = append(parseOpts, tcap.WithTolerance(&ber.ViolationLog{}))
			}
			var w wire.TCMessage
			err := w.UnmarshalBER(data, opts...)
			var failure *wire.DecodeError
			if !errors.Is(err, ber.ErrResourceLimit) || !errors.As(err, &failure) {
				t.Fatalf("expected codec limit: %v", err)
			}
			pe := reviewFailure(t, hex.EncodeToString(data), parseOpts...)
			var otid, dtid []byte
			if failure.Prefix.Otid != nil {
				otid = *failure.Prefix.Otid
			}
			if failure.Prefix.Dtid != nil {
				dtid = *failure.Prefix.Dtid
			}
			if !errors.Is(pe, ber.ErrResourceLimit) || !bytes.Equal(pe.OTID, otid) || !bytes.Equal(pe.DTID, dtid) {
				t.Fatalf("limit %+v tolerant %t: %v, IDs %s/%s, want %x/%x", limits, tolerant, pe, pe.OTID, pe.DTID, otid, dtid)
			}
		}
	}
}

// Only a codec limit skips the Table 7 repeat scan. A limit reached later
// during failure inspection still counts the immediate tags within budget.
func TestProcedureInspectionLimitCountsRepeatedPrefix(t *testing.T) {
	for _, tc := range []struct {
		input, otid, dtid string
		maxWork           int
	}{
		{"620e4801016803040102300430020500", "", "", 10},
		{"65114801014901026903040103300430020500", "01", "", 13},
	} {
		for _, limits := range []ber.DecodeLimits{{MaxDepth: 2}, {MaxElements: 4}, {MaxElements: 5}, {MaxWork: tc.maxWork}} {
			var w wire.TCMessage
			codecErr := w.UnmarshalBER(hx(tc.input), ber.WithDecodeLimits(limits))
			if codecErr == nil || errors.Is(codecErr, ber.ErrResourceLimit) {
				t.Fatalf("expected non-limit codec failure: %v", codecErr)
			}
			pe := reviewFailure(t, tc.input, tcap.WithDecodeLimits(limits))
			if !errors.Is(pe, ber.ErrResourceLimit) || pe.Portion != tcap.PortionTransaction || pe.OTID.String() != tc.otid || pe.DTID.String() != tc.dtid {
				t.Fatalf("%s, limits %+v: %v, IDs %s/%s, want %s/%s", tc.input, limits, pe, pe.OTID, pe.DTID, tc.otid, tc.dtid)
			}
		}
	}
	// The duplicate DTID child ends beyond MaxWork 10, so it is not counted.
	pe := reviewFailure(t, "65114801014901026903040103300430020500", tcap.WithDecodeLimits(ber.DecodeLimits{MaxWork: 10}))
	if !errors.Is(pe, ber.ErrResourceLimit) || pe.OTID.String() != "01" || pe.DTID.String() != "02" {
		t.Fatalf("unread duplicate changed Prefix: %v, IDs %s/%s", pe, pe.OTID, pe.DTID)
	}
}
