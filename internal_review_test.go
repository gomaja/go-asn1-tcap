package tcap

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
)

func TestInternalReviewF5CloneBits(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   runtime.BitString
		want runtime.BitString
	}{
		{"MaxInt", runtime.BitString{Bytes: []byte{0x80}, BitLength: math.MaxInt}, runtime.BitString{Bytes: []byte{0x80}, BitLength: math.MaxInt}},
		{"negative", runtime.BitString{Bytes: []byte{0x80}, BitLength: -1}, runtime.BitString{Bytes: []byte{0x80}, BitLength: -1}},
		{"zero", runtime.BitString{Bytes: []byte{0xff}, BitLength: 0}, runtime.BitString{Bytes: []byte{}, BitLength: 0}},
		{"short", runtime.BitString{Bytes: []byte{0xff}, BitLength: 9}, runtime.BitString{Bytes: []byte{0xff}, BitLength: 9}},
		{"long", runtime.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 1}, runtime.BitString{Bytes: []byte{0x80}, BitLength: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("cloneBits panicked: %v", p)
				}
			}()
			got := cloneBits(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("cloneBits = %+v; want %+v", got, tc.want)
			}
			if len(got.Bytes) > 0 {
				before := tc.in.Bytes[0]
				got.Bytes[0] ^= 0xff
				if tc.in.Bytes[0] != before {
					t.Fatal("cloneBits aliases its input")
				}
			}
		})
	}
}

func TestInternalReviewF11JoinedErrorTraversal(t *testing.T) {
	_, err := Parse([]byte{0x63, 0})
	var multi interface{ Unwrap() []error }
	if !errors.As(err, &multi) || len(multi.Unwrap()) != 2 {
		t.Fatalf("joined causes = %v", err)
	}
	fe := &FieldError{Path: "Dialogue", Err: ErrUnexpectedDialoguePDU}
	joined := joinErrors(ErrUnrecognizedMessageType, fe)
	var got *FieldError
	if !errors.As(joined, &got) || got != fe || !errors.Is(joined, ErrUnexpectedDialoguePDU) {
		t.Fatalf("joined FieldError is unreachable: %v", joined)
	}
}

// The scan of a message's children keeps within the caller's MaxWork, ends
// at the end-of-contents indicator of indefinite contents (ITU-T Q.773
// (06/97) clause 4.1.2.3), and keeps only the leading children.
func TestInternalReview3ScanChildren(t *testing.T) {
	contents := append([]byte{0x48, 0x01, 0x01}, bytes.Repeat([]byte{0x30, 0x02, 0x05, 0x00}, 1000)...)
	contents = append(contents, 0x00, 0x00, 0x48, 0x01, 0x02)
	limits := ber.DefaultDecodeLimits()
	children, err := scanChildren(contents, true, limits)
	if err != nil || children.count != 1001 || children.idCount != [2]int{1, 0} || len(children.leading) != leadingChildren {
		t.Fatalf("indefinite: %d children, %d kept, IDs %v, %v", children.count, len(children.leading), children.idCount, err)
	}
	limits.MaxWork = 8
	children, err = scanChildren(contents, true, limits)
	if !errors.Is(err, ber.ErrResourceLimit) || children.count != 2 {
		t.Fatalf("MaxWork 8: %d children, %v", children.count, err)
	}
	// No element is read once the octets of MaxWork are used.
	limits.MaxWork = 3
	children, err = scanChildren([]byte{0x48, 0x01, 0x01, 0x48, 0x05, 0x01}, false, limits)
	if !errors.Is(err, ber.ErrResourceLimit) || children.count != 1 || children.idCount != [2]int{1, 0} {
		t.Fatalf("MaxWork 3: %d children, IDs %v, %v", children.count, children.idCount, err)
	}
	// MaxElements counts the elements inside the children as well.
	nested := bytes.Repeat([]byte{0x30, 0x80, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00}, 3)
	limits = ber.DefaultDecodeLimits()
	limits.MaxElements = 6
	children, err = scanChildren(nested, false, limits)
	if !errors.Is(err, ber.ErrResourceLimit) || children.count != 1 {
		t.Fatalf("MaxElements 6: %d children, %v", children.count, err)
	}
}

// elementLength finds the end of a BER element from its headers: a definite
// length directly, indefinite contents at their matching end-of-contents
// indicator (X.690 (02/2021) clauses 8.1.3 and 8.1.5), within the limits.
func TestInternalReview3ElementLength(t *testing.T) {
	limits := ber.DefaultDecodeLimits()
	depth3, depth4 := limits, limits
	depth3.MaxDepth, depth4.MaxDepth = 3, 4
	work4, work5 := limits, limits
	work4.MaxWork, work5.MaxWork = 4, 5
	single := limits
	single.MaxElements = 1
	for _, tc := range []struct {
		name   string
		in     []byte
		limits ber.DecodeLimits
		want   int
		err    error
	}{
		{"primitive", []byte{0x05, 0x00, 0xff}, limits, 2, nil},
		{"long-form length", []byte{0x04, 0x81, 0x02, 0x01, 0x02}, limits, 5, nil},
		{"indefinite", []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0xff}, limits, 6, nil},
		{"nested indefinite", []byte{0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00}, limits, 8, nil},
		{"definite inside indefinite", []byte{0x30, 0x80, 0x30, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00}, limits, 9, nil},
		{"indefinite primitive", []byte{0x04, 0x80, 0x00, 0x00}, limits, 0, ber.ErrInvalidLength},
		{"truncated contents", []byte{0x30, 0x05, 0x05, 0x00}, limits, 0, ber.ErrTruncated},
		{"no end-of-contents", []byte{0x30, 0x80, 0x05, 0x00}, limits, 0, ber.ErrTruncated},
		{"nested primitive indefinite", []byte{0x30, 0x80, 0x05, 0x80, 0x00, 0x00, 0x00, 0x00}, limits, 8, nil},
		{"depth", []byte{0x30, 0x80, 0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, depth3, 0, ber.ErrResourceLimit},
		{"depth with the message", []byte{0x30, 0x80, 0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, depth4, 12, nil},
		{"work", []byte{0x04, 0x03, 0x01, 0x02, 0x03}, work4, 0, ber.ErrResourceLimit},
		{"work within the limit", []byte{0x04, 0x03, 0x01, 0x02, 0x03}, work5, 5, nil},
		{"elements", []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00}, single, 0, ber.ErrResourceLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (&scanBudget{limits: tc.limits}).elementLength(tc.in)
			if got != tc.want || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
				t.Fatalf("elementLength = %d, %v; want %d, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

// leadingWithinLimits counts the leading elements of a message as the
// decoder counts them: the message and every element inside them against
// MaxElements, the levels from the message against MaxDepth, and their
// octets against MaxWork.
func TestInternalReview3LeadingWithinLimits(t *testing.T) {
	primitive := []byte{0x48, 0x01, 0x01}
	segmented := []byte{0x68, 0x03, 0x04, 0x01, 0x01}
	indefinite := []byte{0x68, 0x80, 0x04, 0x01, 0x01, 0x00, 0x00}
	limits := func(depth, elements, work int) ber.DecodeLimits {
		return ber.DecodeLimits{MaxDepth: depth, MaxElements: elements, MaxWork: work}
	}
	for _, tc := range []struct {
		name     string
		elements [][]byte
		limits   ber.DecodeLimits
		want     bool
	}{
		{"primitive", [][]byte{primitive}, limits(1, 2, 3), true},
		{"primitive elements", [][]byte{primitive}, limits(1, 1, 3), false},
		{"primitive work", [][]byte{primitive}, limits(1, 2, 2), false},
		{"segmented", [][]byte{segmented}, limits(2, 3, 5), true},
		{"segmented depth", [][]byte{segmented}, limits(1, 3, 5), false},
		{"segmented elements", [][]byte{segmented}, limits(2, 2, 5), false},
		{"indefinite", [][]byte{indefinite}, limits(2, 3, 7), true},
		{"two elements", [][]byte{segmented, primitive}, limits(2, 4, 8), true},
		{"two elements beyond", [][]byte{segmented, primitive}, limits(2, 3, 8), false},
		{"truncated", [][]byte{{0x68, 0x05, 0x04, 0x01, 0x01}}, limits(2, 9, 9), false},
		{"segment past its parent", [][]byte{{0x68, 0x02, 0x04, 0x01, 0x01}}, limits(2, 9, 9), false},
		{"no end-of-contents", [][]byte{{0x68, 0x80, 0x04, 0x01, 0x01}}, limits(2, 9, 9), false},
	} {
		if got := leadingWithinLimits(tc.elements, tc.limits); got != tc.want {
			t.Errorf("%s: %t, want %t", tc.name, got, tc.want)
		}
	}
}

// transactionIDValue reads a transaction ID as ber.DecodeOctetString reads
// an OCTET STRING (X.690 (02/2021) clause 8.7), each octet once.
func TestInternalReview3TransactionIDValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"primitive", "480401020304", "01020304", true},
		{"empty", "4800", "", true},
		{"segments", "68080402010204020304", "01020304", true},
		{"indefinite segments", "688004020102040203040000", "01020304", true},
		{"nested segments", "680a24080402010204020304", "01020304", true},
		{"nested", "680c240a04020102040203040000", "", false},
		{"nested definite", "680a2408040201020402030400"[:20], "", false},
		{"nested in indefinite", "6880240804020102040203040000", "01020304", true},
		{"no segments", "6800", "", true},
		{"segment not OCTET STRING", "6803020101", "", false},
		{"end-of-contents across a bound", "6805248004000000", "", false},
		{"segment past its parent", "6803040201", "", false},
		{"primitive indefinite segment", "688004800000", "", false},
		{"trailing octets", "4801010000", "", false},
		{"no end-of-contents", "6880040101", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, _ := hex.DecodeString(tc.in)
			got, ok := transactionIDValue(in, ber.DefaultDecodeLimits().MaxDepth, -1)
			if ok != tc.ok || ok && hex.EncodeToString(got) != tc.want {
				t.Fatalf("transactionIDValue(%s) = %x, %t; want %s, %t", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
	for _, tc := range []struct {
		in     string
		maxLen int
		ok     bool
	}{
		{"480401020304", 4, true},
		{"48050102030405", 4, false},
		{"68080402010204020304", 4, true},
		{"6809040201020403030405", 4, false},
		{"6809040201020403030405", -1, true},
		{"48050102030405", -1, true},
	} {
		in, _ := hex.DecodeString(tc.in)
		if _, ok := transactionIDValue(in, ber.DefaultDecodeLimits().MaxDepth, tc.maxLen); ok != tc.ok {
			t.Errorf("transactionIDValue(%s, maxLen %d) ok = %t", tc.in, tc.maxLen, ok)
		}
	}
	deep := "0401aa"
	for range 3 {
		deep = "2480" + deep + "0000"
	}
	in, _ := hex.DecodeString("6880" + deep + "0000")
	if _, ok := transactionIDValue(in, 3, -1); ok {
		t.Fatal("a segment nested deeper than maxDepth accepted")
	}
	if got, ok := transactionIDValue(in, 4, -1); !ok || hex.EncodeToString(got) != "aa" {
		t.Fatalf("segments within maxDepth: %x, %t", got, ok)
	}
}

// FuzzTransactionIDValue: transactionIDValue never panics and agrees with
// the value ber.DecodeImplicitOctetStringValue decodes from the same element.
func FuzzTransactionIDValue(f *testing.F) {
	for _, s := range []string{"480401020304", "680a0402010204020304", "688004020102040203040000", "6880240804020102040203040000", "68062480040000000000"} {
		in, _ := hex.DecodeString(s)
		f.Add(in)
	}
	f.Fuzz(func(t *testing.T, element []byte) {
		got, ok := transactionIDValue(element, ber.DefaultDecodeLimits().MaxDepth, -1)
		tg, n, value, err := ber.DecodeTLV(element)
		if err != nil || n != len(element) {
			if ok {
				t.Fatalf("%x: accepted %x, but DecodeTLV: %d, %v", element, got, n, err)
			}
			return
		}
		want, err := ber.DecodeImplicitOctetStringValue(tg.Constructed, value, ber.WithDecodeLimits(ber.DecodeLimits{MaxWork: 1 << 24}))
		if ok != (err == nil) || ok && !bytes.Equal(got, want) {
			t.Fatalf("%x: %x, %t; decoder %x, %v", element, got, ok, want, err)
		}
	})
}
