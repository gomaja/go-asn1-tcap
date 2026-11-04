package tcap_test

import (
	"errors"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// X.690 (02/2021) clauses 8.1.3.6 and 8.1.5 end an indefinite message at
// its matching EOC. Q.774 (06/97) Table 7 derives IDs from that message only.
func TestParseInspectionExtent(t *testing.T) {
	const bad = tcap.PAbortCauseBadlyFormattedTransactionPortion
	const resource = tcap.PAbortCauseResourceLimitation
	for _, tc := range []struct {
		name, input string
		portion     tcap.Portion
		index       int
		otid, dtid  string
		cause       int64
		limits      tcap.DecodeLimits
		codecLimit  bool
	}{
		{name: "NULL after malformed indefinite message", input: "62804801016c80a106020101020101a180058000000000000000000500", portion: tcap.PortionTransaction, index: -1, otid: "01", cause: bad},
		{name: "OTID after malformed indefinite message", input: "62804801016c80a18005800000000000000000480102", portion: tcap.PortionTransaction, index: -1, otid: "01", cause: bad},
		{name: "IDs after malformed indefinite Continue", input: "65804801014901026c80a18005800000000000000000480103490104", portion: tcap.PortionTransaction, index: -1, otid: "01", dtid: "02", cause: bad},
		{name: "malformed indefinite message alone", input: "62804801016c80a18005800000000000000000", portion: tcap.PortionComponent, index: 0, otid: "01"},
		{name: "repeated OTID inside message", input: "62804801014801026c80a18005800000000000000000", portion: tcap.PortionTransaction, index: -1, cause: bad},
		{name: "OTID after well formed indefinite message", input: "62804801016c80a10602010102010100000000480102", portion: tcap.PortionTransaction, index: -1, otid: "01", cause: bad},
		{name: "no matching EOC", input: "62804801016c80a1800580", portion: tcap.PortionComponent, index: 0, otid: "01"},
		{name: "OCTET STRING containing zeros", input: "62804801016c80a1800402000005800000000000000000", portion: tcap.PortionComponent, index: 0, otid: "01"},
		{name: "OTID after OCTET STRING containing zeros", input: "62804801016c80a1800402000005800000000000000000480102", portion: tcap.PortionTransaction, index: -1, otid: "01", cause: bad},
		// The codec stops at the primitive indefinite NULL. Lenient
		// delimiting continues within the same limits; its limit does not
		// change the codec's cause (Q.774 (06/97) Figure A.3).
		{name: "delimiting element limit", input: "62804801014801026c80a180058000000000000005000000480103", limits: tcap.DecodeLimits{MaxElements: 6}, portion: tcap.PortionTransaction, index: -1, cause: bad},
		{name: "delimiting depth limit", input: "62804801014801026c80a180058000000000000005000000480103", limits: tcap.DecodeLimits{MaxDepth: 3}, portion: tcap.PortionTransaction, index: -1, cause: bad},
		{name: "delimiting work limit", input: "62804801014801026c80a180058000000000000005000000480103", limits: tcap.DecodeLimits{MaxWork: 16}, portion: tcap.PortionTransaction, index: -1, cause: bad},
		{name: "element limit retains component location", input: "62804801016c80a180058000000500000000000000480102", limits: tcap.DecodeLimits{MaxElements: 5}, portion: tcap.PortionComponent, index: 0, otid: "01"},
		{name: "depth limit retains component location", input: "62804801016c80a18005800000000000000000480102", limits: tcap.DecodeLimits{MaxDepth: 3}, portion: tcap.PortionComponent, index: 0, otid: "01"},
		{name: "work limit retains component location", input: "62804801016c80a18005800000000000000000480102", limits: tcap.DecodeLimits{MaxWork: 12}, portion: tcap.PortionComponent, index: 0, otid: "01"},
		{name: "work limit at message EOC", input: "62804801016c80a18005800000000000000000", limits: tcap.DecodeLimits{MaxWork: 16}, portion: tcap.PortionTransaction, index: -1, otid: "01", cause: bad},
		{name: "work includes message EOC", input: "62804801016c80a18005800000000000000000", limits: tcap.DecodeLimits{MaxWork: 17}, portion: tcap.PortionComponent, index: 0, otid: "01"},
		{name: "codec element limit", input: "62804801016c80a18005800000000000000000480102", limits: tcap.DecodeLimits{MaxElements: 4}, codecLimit: true, portion: tcap.PortionTransaction, index: -1, otid: "01", cause: resource},
		{name: "codec depth limit", input: "62804801016c80a18005800000000000000000480102", limits: tcap.DecodeLimits{MaxDepth: 2}, codecLimit: true, portion: tcap.PortionTransaction, index: -1, otid: "01", cause: resource},
		{name: "codec work limit", input: "62804801016c80a18005800000000000000000480102", limits: tcap.DecodeLimits{MaxWork: 10}, codecLimit: true, portion: tcap.PortionTransaction, index: -1, otid: "01", cause: resource},
		{name: "transaction layout before dialogue failure", input: "61146b09280706012aa00205006c05a1030201050500", portion: tcap.PortionTransaction, index: -1, cause: tcap.PAbortCauseIncorrectTransactionPortion},
	} {
		for _, mode := range []string{"strict", "tolerant"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				var opts []tcap.ParseOption
				var codecOpts []ber.DecodeOption
				var log tcap.ViolationLog
				if mode == "tolerant" {
					opts = append(opts, tcap.WithTolerance(&log))
					codecOpts = append(codecOpts, ber.WithTolerance(&ber.ViolationLog{}))
				}
				if tc.limits != (tcap.DecodeLimits{}) {
					opts = append(opts, tcap.WithDecodeLimits(tc.limits))
					codecOpts = append(codecOpts, ber.WithDecodeLimits(tc.limits))
				}
				raw := hx(tc.input)
				var w wire.TCMessage
				codecErr := w.UnmarshalBER(raw, codecOpts...)
				if codecErr == nil || errors.Is(codecErr, ber.ErrResourceLimit) != tc.codecLimit {
					t.Fatalf("codec failure = %v, want resource limit %t", codecErr, tc.codecLimit)
				}
				msg, err := tcap.Parse(raw, opts...)
				var pe *tcap.ParseError
				if msg != nil || !errors.As(err, &pe) {
					t.Fatalf("Parse = %v, %v", msg, err)
				}
				if pe.Portion != tc.portion || pe.ComponentIndex != tc.index {
					t.Errorf("Portion = %s, ComponentIndex = %d; want %s, %d: %v", pe.Portion, pe.ComponentIndex, tc.portion, tc.index, err)
				}
				if pe.OTID.String() != tc.otid || (pe.OTID == nil) != (tc.otid == "") || pe.DTID.String() != tc.dtid || (pe.DTID == nil) != (tc.dtid == "") {
					t.Errorf("OTID = %s, DTID = %s; want %s, %s", pe.OTID, pe.DTID, tc.otid, tc.dtid)
				}
				cause, ok := pe.PAbortCause()
				if ok != (tc.portion == tcap.PortionTransaction) {
					t.Errorf("PAbortCause ok = %t: %v", ok, err)
				} else if ok {
					if value, fits := cause.AsInt64(); !fits || value != tc.cause {
						t.Errorf("PAbortCause = %v; want %d: %v", cause, tc.cause, err)
					}
				}
				if len(log.Snapshot()) != 0 {
					t.Fatal("failure published violations")
				}
			})
		}
	}
}

// Q.773 (06/97) clause 4.2.3 distinguishes structured and unstructured
// dialogue syntax. An incorrect dialogue portion aborts the dialogue (Q.774
// (06/97) clause 3.2.2.1), so it goes before a component failure.
func TestParseInspectionDialogueFailure(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{name: "malformed component", input: "61126b09280706012aa00205006c05a103020105"},
		{name: "valid component", input: "61156b09280706012aa00205006c08a106020101020101", valid: true},
	} {
		for _, mode := range []string{"strict", "tolerant"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				var opts []tcap.ParseOption
				var log tcap.ViolationLog
				if mode == "tolerant" {
					opts = append(opts, tcap.WithTolerance(&log))
				}
				msg, err := tcap.Parse(hx(tc.input), opts...)
				if mode == "tolerant" && tc.valid {
					if err != nil || msg == nil {
						t.Fatalf("Parse = %v, %v", msg, err)
					}
					return
				}
				var pe *tcap.ParseError
				if msg != nil || !errors.As(err, &pe) {
					t.Fatalf("Parse = %v, %v", msg, err)
				}
				portion, index := tcap.PortionDialogue, -1
				if mode == "tolerant" {
					portion, index = tcap.PortionComponent, 0
				}
				if pe.Portion != portion || pe.ComponentIndex != index || (pe.Dialogue != nil) != (mode == "tolerant") {
					t.Errorf("Portion = %s, ComponentIndex = %d, Dialogue = %+v; want %s, %d, dialogue %t", pe.Portion, pe.ComponentIndex, pe.Dialogue, portion, index, mode == "tolerant")
				}
				if mode == "tolerant" && (pe.Dialogue == nil || pe.Dialogue.Opaque == nil || pe.Dialogue.Opaque.DirectReference != "1.2") {
					t.Errorf("want the tolerated foreign dialogue: %+v", pe.Dialogue)
				}
				if pe.OTID != nil || pe.DTID != nil {
					t.Errorf("unexpected IDs: OTID = %s, DTID = %s", pe.OTID, pe.DTID)
				}
				if _, ok := pe.PAbortCause(); ok {
					t.Error("unexpected P-Abort cause")
				}
				if mode == "strict" {
					var v *ber.ValidationError
					var decoded *wire.DecodeError
					if !errors.As(pe.Err, &decoded) || !errors.As(pe.Err, &v) || v.Rule.Document != "ITU-T Q.773" || v.Rule.Clause != "4.2.3" || v.Offset == nil || *v.Offset != 2 || len(v.ChildIndexes) != 1 || v.ChildIndexes[0] != 0 {
						t.Errorf("want codec dialogue validation for Q.773 clause 4.2.3: %v", pe.Err)
					}
				}
				if len(log.Snapshot()) != 0 {
					t.Fatal("failure published violations")
				}
			})
		}
	}
}

// Q.773 (06/97) clause 4.1.1 requires short lengths below 128. Inspection
// decodes a dialogue portion on its own, but only individual components.
func TestParseInspectionPortionLengthForm(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		portion     tcap.Portion
	}{
		{name: "dialogue", input: "640f4901016b8109280706012aa0020500", portion: tcap.PortionDialogue},
		{name: "components", input: "640e4901016c8108a106020101020101", portion: tcap.PortionTransaction},
	} {
		for _, mode := range []string{"strict", "tolerant"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				var opts []tcap.ParseOption
				if mode == "tolerant" {
					opts = append(opts, tcap.WithTolerance(&tcap.ViolationLog{}))
				}
				msg, err := tcap.Parse(hx(tc.input), opts...)
				if mode == "tolerant" {
					if err != nil || msg == nil {
						t.Fatalf("Parse = %v, %v", msg, err)
					}
					mustMarshal(t, msg)
					return
				}
				var pe *tcap.ParseError
				if msg != nil || !errors.As(err, &pe) {
					t.Fatalf("Parse = %v, %v", msg, err)
				}
				if pe.Portion != tc.portion || pe.ComponentIndex != -1 || pe.OTID != nil || pe.DTID.String() != "01" {
					t.Errorf("Portion = %s, ComponentIndex = %d, OTID = %s, DTID = %s; want %s, -1, nil, 01", pe.Portion, pe.ComponentIndex, pe.OTID, pe.DTID, tc.portion)
				}
				cause, ok := pe.PAbortCause()
				if ok != (tc.portion == tcap.PortionTransaction) {
					t.Errorf("PAbortCause ok = %t: %v", ok, err)
				} else if ok {
					if value, fits := cause.AsInt64(); !fits || value != tcap.PAbortCauseBadlyFormattedTransactionPortion {
						t.Errorf("PAbortCause = %v; want badlyFormatted: %v", cause, err)
					}
				}
			})
		}
	}
}
