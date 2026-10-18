package tcap_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// parseErrorContinueHex is a Continue (OTID 01020304, DTID 05060708) with an
// accepting AARE, a valid Invoke (invoke ID 1, operation 45) and a second
// Invoke a1 03 02 01 05 that has an invoke ID of 5 but no operation code,
// which X.880 (07/94) Invoke requires.
const parseErrorContinueHex = "654e4804010203044904050607086b2a2828060700118605010101a01d611b80020780a109060704000001001403a203020100a305a1030201006c14a10d02010102012d30050403010203a103020105"

var idx1 = ptr(1)

// checkErrorContext checks the Dialogue and Components of a ParseError:
// the decoded dialogue portion and the valid components that precede the
// failing one (errors.go; ITU-T Q.774 (06/97) clause 3.2.2.2).
func checkErrorContext(t *testing.T, pe *tcap.ParseError, dialogue *tcap.Dialogue, components []tcap.Component) {
	t.Helper()
	if got, want := canonicalJSON(t, normDialogue(pe.Dialogue)), canonicalJSON(t, normDialogue(dialogue)); !reflect.DeepEqual(got, want) {
		t.Errorf("ParseError.Dialogue:\n got %s\nwant %s", jsonText(got), jsonText(want))
	}
	if got, want := canonicalJSON(t, normComponents(pe.Components)), canonicalJSON(t, normComponents(components)); !reflect.DeepEqual(got, want) {
		t.Errorf("ParseError.Components:\n got %s\nwant %s", jsonText(got), jsonText(want))
	}
}

func TestParseErrorComponentContext(t *testing.T) {
	aare := aareD(pv1(), true)
	continueWant := func(index *int, invokeID string, constraint bool) parseErrWant {
		return parseErrWant{
			portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeContinue},
			otid: "01020304", dtid: "05060708", compIndex: index, invokeID: invokeID, constraint: constraint,
		}
	}

	t.Run("second component malformed", func(t *testing.T) {
		msg, err := tcap.Parse(hx(parseErrorContinueHex))
		if msg != nil {
			t.Error("Parse returned a message with the error")
		}
		checkParseError(t, err, continueWant(idx1, "5", false))
		checkErrorContext(t, asParseError(t, err), aare, []tcap.Component{invokeC(1)})
	})

	t.Run("components after the failing one are discarded", func(t *testing.T) {
		third := "a10d02010702013c30050403010203"
		input := tlv("65", hexOTID, hexDTID, dialoguePortion(hexDialogueAS, hexAAREAcc), tlv("6c", hexInvoke, "a103020105", third))
		_, err := tcap.Parse(hx(input))
		checkParseError(t, err, continueWant(idx1, "5", false))
		checkErrorContext(t, asParseError(t, err), aare, []tcap.Component{invokeC(1)})
	})

	// The second invoke ID is 128 (02 02 00 80), outside -128..127, so it is
	// not derivable (contract 4.5).
	t.Run("second invoke ID out of range", func(t *testing.T) {
		input := "65524804010203044904050607086b2a2828060700118605010101a01d611b80020780a109060704000001001403a203020100a305a1030201006c18a10d02010102012d30050403010203a1070202008002012d"
		_, err := tcap.Parse(hx(input))
		checkParseError(t, err, continueWant(idx1, "", true))
		checkErrorContext(t, asParseError(t, err), aare, []tcap.Component{invokeC(1)})
	})

	t.Run("first component malformed, no dialogue", func(t *testing.T) {
		input := tlv("64", hexDTID, tlv("6c", "a103020109"))
		_, err := tcap.Parse(hx(input))
		checkParseError(t, err, parseErrWant{
			portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeEnd},
			otid: unchecked, dtid: "05060708", compIndex: idx0, invokeID: "9",
		})
		checkErrorContext(t, asParseError(t, err), nil, nil)
	})

	// The first child of the failing component is not an INTEGER.
	t.Run("invoke ID not derivable", func(t *testing.T) {
		input := tlv("62", hexOTID, tlv("6c", hexInvoke, "a1030401aa"))
		_, err := tcap.Parse(hx(input))
		checkParseError(t, err, parseErrWant{
			portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
			otid: "01020304", dtid: unchecked, compIndex: idx1, invokeID: "",
		})
	})
}

// TestParseErrorUnrecognizedComponent: a component tag outside Q.773 Table 19
// ([1], [2], [3], [4], [7], constructed context-specific) is reported with
// ErrUnrecognizedComponent at its index (contract 4.5).
func TestParseErrorUnrecognizedComponent(t *testing.T) {
	cases := []struct {
		name, input string
		index       *int
		prefix      []tcap.Component
	}{
		{"tag [5] after a valid invoke", "621c4804010203046c14a10d02010102012d30050403010203a503020101", idx1, []tcap.Component{invokeC(1)}},
		{"primitive [1]", "620d4804010203046c058103020101", idx0, nil},
		{"universal SEQUENCE", tlv("62", hexOTID, tlv("6c", "3003020101")), idx0, nil},
		{"application class", tlv("62", hexOTID, tlv("6c", hexInvoke, "6103020101")), idx1, []tcap.Component{invokeC(1)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := tcap.Parse(hx(c.input))
			checkParseError(t, err, parseErrWant{
				portions: []tcap.Portion{tcap.PortionComponent}, msgTypes: []tcap.MessageType{tcap.MessageTypeBegin},
				otid: "01020304", dtid: unchecked, compIndex: c.index, invokeID: unchecked, is: tcap.ErrUnrecognizedComponent,
			})
			checkErrorContext(t, asParseError(t, err), nil, c.prefix)
		})
	}
}

// TestParseErrorUnrecognizedMessageType: a message tag outside Q.773 Table 8;
// the transaction IDs are still derived when the TLV is well-formed (ITU-T
// Q.774 (06/97) Table 7, row UNKNOWN; contract 4.5).
func TestParseErrorUnrecognizedMessageType(t *testing.T) {
	cases := []struct{ name, input, otid, dtid string }{
		{"[APPLICATION 6] with OTID and DTID", "661d4804010203044904050607086c0fa10d02010102012d30050403010203", "01020304", "05060708"},
		{"universal SEQUENCE with OTID", "30174804010203046c0fa10d02010102012d30050403010203", "", ""},
		{"primitive [APPLICATION 2]", "420401020304", "", ""},
		{"[APPLICATION 3] empty", "6300", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := tcap.Parse(hx(c.input))
			checkParseError(t, err, parseErrWant{
				portions: []tcap.Portion{tcap.PortionTransaction}, msgTypes: []tcap.MessageType{""},
				otid: c.otid, dtid: c.dtid, invokeID: unchecked, is: tcap.ErrUnrecognizedMessageType,
			})
		})
	}
}

// TestParseErrorTransactionPortion: failures that no single portion explains
// are in the transaction portion (contract 4.5).
func TestParseErrorTransactionPortion(t *testing.T) {
	cases := []struct {
		name, input string
		want        parseErrWant
	}{
		{"trailing octet after an Abort", "67094904050607084a010100", parseErrWant{
			msgTypes: []tcap.MessageType{tcap.MessageTypeAbort}, otid: unchecked, dtid: "05060708", invokeID: unchecked,
		}},
		{"two messages", "67094904050607084a010167094904050607084a0101", parseErrWant{
			msgTypes: []tcap.MessageType{tcap.MessageTypeAbort}, otid: unchecked, dtid: "05060708", invokeID: unchecked,
		}},
		{"truncated inside the DTID", "670949040506", parseErrWant{otid: unchecked, dtid: "", invokeID: unchecked}},
		{"tag only", "62", parseErrWant{otid: "", dtid: "", invokeID: unchecked}},
		// Q.773 Table 4: the OTID comes first in a Begin.
		{"Begin without OTID", tlv("62", tlv("6c", hexInvoke)), parseErrWant{
			msgTypes: []tcap.MessageType{tcap.MessageTypeBegin}, otid: "", dtid: unchecked, invokeID: unchecked,
		}},
		{"End without DTID", tlv("64", tlv("6c", "a203020101")), parseErrWant{
			msgTypes: []tcap.MessageType{tcap.MessageTypeEnd}, otid: unchecked, dtid: "", invokeID: unchecked,
		}},
		{"Continue with DTID before OTID", tlv("65", hexDTID, hexOTID, tlv("6c", hexInvoke)), parseErrWant{
			msgTypes: []tcap.MessageType{tcap.MessageTypeContinue}, otid: unchecked, dtid: unchecked, invokeID: unchecked,
		}},
		{"Begin with two OTIDs", tlv("62", hexOTID, hexOTID, tlv("6c", hexInvoke)), parseErrWant{
			msgTypes: []tcap.MessageType{tcap.MessageTypeBegin}, otid: unchecked, dtid: unchecked, invokeID: unchecked,
		}},
		// The DTID is empty, so not derivable; the OTID is.
		{"Continue with empty DTID", "651948040102030449006c0fa10d02010102012d30050403010203", parseErrWant{
			msgTypes: []tcap.MessageType{tcap.MessageTypeContinue}, otid: "01020304", dtid: "", invokeID: unchecked, constraint: true,
		}},
		// Strict decoding refuses the 5-octet OTID before accepting either ID.
		{"Continue with 5-octet OTID", "651e480501020304054904050607086c0fa10d02010102012d30050403010203", parseErrWant{
			msgTypes: []tcap.MessageType{tcap.MessageTypeContinue}, otid: "", dtid: "", invokeID: unchecked, constraint: true,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.want.portions = []tcap.Portion{tcap.PortionTransaction}
			_, err := tcap.Parse(hx(c.input))
			checkParseError(t, err, c.want)
		})
	}
}

// TestParseErrorWrapping: callers inspect a ParseError with errors.As and its
// cause with errors.Is, also when it is wrapped further.
func TestParseErrorWrapping(t *testing.T) {
	_, err := tcap.Parse(hx(corpusHex(t, "begin-linked-absent")))
	if err == nil {
		t.Fatal("Parse succeeded")
	}
	if err.Error() == "" {
		t.Error("Error() is empty")
	}
	wrapped := fmt.Errorf("dialogue 7: %w", fmt.Errorf("receive: %w", err))
	var pe *tcap.ParseError
	if !errors.As(wrapped, &pe) {
		t.Fatal("errors.As(*tcap.ParseError) failed through wrapping")
	}
	var validation *ber.ValidationError
	if !errors.As(wrapped, &validation) || !errors.Is(wrapped, ber.ErrInvalidValue) {
		t.Error("codec ValidationError failed through wrapping")
	}
	if pe.Unwrap() != pe.Err || !errors.Is(pe.Err, ber.ErrInvalidValue) {
		t.Errorf("Unwrap = %v, Err = %v", pe.Unwrap(), pe.Err)
	}
	if errors.Is(wrapped, tcap.ErrMissingInvokeID) {
		t.Error("errors.Is matches an unrelated sentinel")
	}

	_, err = tcap.Parse(hx(corpusHex(t, "negative-otid-5")))
	var ce *ber.ValidationError
	if !errors.As(fmt.Errorf("outer: %w", err), &ce) {
		t.Errorf("errors.As(*ber.ValidationError) failed through wrapping: %v", err)
	}

	// A FieldError from Marshal, likewise.
	_, err = beginWith(invokeC(1), tcap.Component{}).Marshal()
	var fe *tcap.FieldError
	if !errors.As(fmt.Errorf("send: %w", err), &fe) {
		t.Fatalf("errors.As(*tcap.FieldError) failed: %v", err)
	}
	if fe.Error() == "" || fe.Unwrap() != fe.Err || !errors.Is(fe, tcap.ErrComponentNoAlternative) {
		t.Errorf("FieldError %q: Unwrap = %v", fe.Error(), fe.Unwrap())
	}
}
