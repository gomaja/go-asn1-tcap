package tcap

import (
	"errors"

	wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
)

// ITU-T Q.774 (06/97) clauses 3.2.2, 3.3.4 and Table 7 require the IDs
// needed to address an Abort or locate the receiving transaction.
func decodeFailureIDs(pe *ParseError, failure *wire.DecodeError, data []byte, opts []ber.DecodeOption, limits ber.DecodeLimits) {
	if failure.Prefix.Otid != nil {
		pe.OTID = append(TransactionID{}, (*failure.Prefix.Otid)...)
	}
	if failure.Prefix.Dtid != nil {
		pe.DTID = append(TransactionID{}, (*failure.Prefix.Dtid)...)
	}
	if pe.MessageType == MessageTypeUnidirectional || pe.MessageType == MessageTypeBegin && pe.OTID != nil || (pe.MessageType == MessageTypeEnd || pe.MessageType == MessageTypeAbort) && pe.DTID != nil || pe.OTID != nil && pe.DTID != nil {
		return
	}
	// A validation failure of the message itself leaves no derivable IDs. A
	// failure that inspection found in a later portion is not one, whatever
	// location the codec gives it: https://github.com/gomaja/go-asn1/issues/166.
	var validation *ber.ValidationError
	var rootFailure *ber.ElementError
	if pe.Portion == PortionTransaction && errors.As(failure, &validation) && errors.As(failure, &rootFailure) && len(rootFailure.ChildIndexes()) == 0 {
		return
	}
	// Inspection must not publish additional tolerance reports.
	opts, _ = ber.StageDecodeReports(opts)
	t, err := ber.PeekTag(data)
	if err != nil || !t.Constructed {
		return
	}
	contents, indefinite := inspectedContents(data)
	var children messageChildren
	limited := errors.Is(pe.Err, ber.ErrResourceLimit)
	if limited {
		var location *ber.ElementError
		if pe.MessageType == "" || !errors.As(pe.Err, &location) || len(location.ChildIndexes()) == 0 {
			return
		}
		// Q.774 clause 3.3.4 and Table 7 use IDs validated before the failure.
		// DecodeError.Prefix omits tolerated IDs: https://github.com/gomaja/go-asn1/issues/162.
		for i := 0; i < min(location.ChildIndexes()[0], 2) && len(contents) > 0; i++ {
			_, n, _, err := ber.DecodeTLV(contents, opts...)
			if err != nil {
				break
			}
			children.add(contents[:n])
			contents = contents[n:]
		}
	} else {
		// Q.774 clause 3.3.4 and Table 7 require IDs for the abnormal procedure.
		// DecodeError.Prefix has no IDs for an unlocated failure or an UNKNOWN message: https://github.com/gomaja/go-asn1/issues/161.
		var err error
		children, err = scanChildren(contents, indefinite, limits)
		if errors.Is(err, ber.ErrResourceLimit) {
			// A limit met while inspecting leaves the elements read before
			// it; an ID is taken from its place without looking for repeats.
			limited = true
			if pe.Portion == PortionTransaction {
				pe.Err = joinErrors(pe.Err, err)
			}
		}
	}
	for i := range 2 {
		if i == 0 && pe.OTID != nil || i == 1 && pe.DTID != nil {
			continue
		}
		pos := tidPosition(pe.MessageType, i)
		var element []byte
		if pe.MessageType == "" && children.idCount[i] == 1 {
			element = children.ids[i]
		} else if pos >= 0 && pos < len(children.leading) && (limited || children.idCount[i] == 1 && children.idPos[i] == pos) {
			element = children.leading[pos]
		}
		if element == nil {
			continue
		}
		// Q.773 clause 3.1 assigns APPLICATION 8 to OTID and APPLICATION 9 to DTID.
		t, err := ber.PeekTag(element)
		if err != nil || t.Class != tag.ClassApplication || t.Number != 8+i {
			continue
		}
		// Q.774 clause 3.2.2 needs the transaction IDs when a later portion fails.
		// DecodeError.Prefix omits tolerated IDs: https://github.com/gomaja/go-asn1/issues/162.
		id, ok := transactionIDValue(element, opts)
		if !ok {
			continue
		}
		if i == 0 {
			pe.OTID = append(TransactionID{}, id...)
		} else {
			pe.DTID = append(TransactionID{}, id...)
		}
	}
}
