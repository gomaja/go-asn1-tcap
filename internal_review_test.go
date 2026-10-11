package tcap

import (
	"bytes"
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
	children, err := scanChildren(contents, true, nil, limits)
	if err != nil || children.count != 1001 || children.idCount != [2]int{1, 0} || len(children.leading) != leadingChildren {
		t.Fatalf("indefinite: %d children, %d kept, IDs %v, %v", children.count, len(children.leading), children.idCount, err)
	}
	limits.MaxWork = 8
	children, err = scanChildren(contents, true, nil, limits)
	if !errors.Is(err, ber.ErrResourceLimit) || children.count != 2 {
		t.Fatalf("MaxWork 8: %d children, %v", children.count, err)
	}
}

// elementLength finds the end of a BER element from its headers: a definite
// length directly, indefinite contents at their matching end-of-contents
// indicator (X.690 (02/2021) clauses 8.1.3 and 8.1.5), within the limits.
func TestInternalReview3ElementLength(t *testing.T) {
	limits := ber.DefaultDecodeLimits()
	shallow := limits
	shallow.MaxDepth = 2
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
		{"depth", []byte{0x30, 0x80, 0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, shallow, 0, ber.ErrResourceLimit},
		{"elements", []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00}, single, 0, ber.ErrResourceLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := elementLength(tc.in, tc.limits)
			if got != tc.want || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
				t.Fatalf("elementLength = %d, %v; want %d, %v", got, err, tc.want, tc.err)
			}
		})
	}
}
