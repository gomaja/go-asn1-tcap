package tcap

import (
	"encoding/hex"
	"errors"
	"testing"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
)

func TestInternalReview4DialogueFailureLocation(t *testing.T) {
	for _, tc := range []struct {
		input    string
		dialogue bool
	}{
		// An Opaque Unidirectional violates the codec's Q.773 clause 4.2.3 rule.
		{"61206b0d280b06032a0304a0040402aabb6c0fa10d02010102012d30050403010203", true},
		// APPLICATION 11 inside a component parameter is not a dialogue portion.
		{"62104801016c0ba1090201010201016b8100", false},
		// A primitive APPLICATION 11 does not form a dialogue portion.
		{"62054801014b00", false},
	} {
		data, err := hex.DecodeString(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		var message wire.TCMessage
		err = message.UnmarshalBER(data)
		var failure *wire.DecodeError
		if !errors.As(err, &failure) {
			t.Fatalf("codec error: %v", err)
		}
		// Error path spelling is independent of the location supplied by the codec.
		failure.Path = "renamed"
		if got := isDialogueFailure(data, failure); got != tc.dialogue {
			t.Errorf("%s: dialogue failure %t, want %t: %v", tc.input, got, tc.dialogue, err)
		}
	}
}
