package tcap

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
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
