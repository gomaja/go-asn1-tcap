package tcap

import (
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
)

func fieldError(path string, err error) error {
	if err == nil {
		return nil
	}
	return &FieldError{Path: path, Err: err}
}

func alternative(count int, none, multiple error) error {
	if count == 0 {
		return none
	}
	if count > 1 {
		return multiple
	}
	return nil
}

func set(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ITU-T Q.774 (06/97) Table 3 governs placement; clause 3.2.3 governs versions.
func validateDialogue(d *Dialogue, mt MessageType, sender bool) error {
	if d == nil {
		return nil
	}
	count := set(d.Request != nil) + set(d.Response != nil) + set(d.Abort != nil) + set(d.Unidirectional != nil) + set(d.Opaque != nil)
	if err := alternative(count, ErrDialogueNoAlternative, ErrDialogueMultipleAlternatives); err != nil {
		return fieldError("Dialogue", err)
	}
	// ITU-T Q.774 (06/97) Table 3 and Figure A.5, sheets 3 and 7: a Begin
	// carries the AARQ, a Continue or an End an AARE, an Abort an AARE or an
	// ABRT. Another abstract syntax may appear in a Continue or an End (clause
	// 3.2.1.2) and in an Abort (Q.773 (06/97) clause 3.1, DialoguePortion).
	allowed := d.Opaque != nil
	switch mt {
	case MessageTypeBegin:
		allowed = d.Request != nil
	case MessageTypeContinue, MessageTypeEnd:
		allowed = allowed || d.Response != nil
	case MessageTypeAbort:
		allowed = allowed || d.Response != nil || d.Abort != nil
	case MessageTypeUnidirectional:
		// Q.773 clause 4.2.3 syntax restrictions belong to the codec.
		allowed = allowed || d.Unidirectional != nil
	}
	if !allowed {
		return fieldError("Dialogue", ErrUnexpectedDialoguePDU)
	}
	if r := d.Response; r != nil {
		// Q.774 Table 3, Note 3 and clauses 3.2.1.2 and 3.2.3: an AARE accepts
		// the dialogue in a Continue or an End and rejects it permanently in an
		// Abort; no other result applies.
		result := r.Result.BigInt()
		accepted := result.Sign() == 0
		if !accepted && result.Cmp(bigOne) != 0 || (mt == MessageTypeAbort) == accepted {
			return fieldError("Dialogue.Response.Result", ErrUnexpectedDialogueResult)
		}
		if !onlyVersion1(r.ProtocolVersion) {
			return fieldError("Dialogue.Response.ProtocolVersion", ErrUnsupportedProtocolVersion)
		}
		count := set(r.ResultSourceDiagnostic.DialogueServiceUser != nil) + set(r.ResultSourceDiagnostic.DialogueServiceProvider != nil)
		if err := alternative(count, ErrResultSourceDiagnosticNoAlternative, ErrResultSourceDiagnosticMultipleAlternatives); err != nil {
			return fieldError("Dialogue.Response.ResultSourceDiagnostic", err)
		}
	}
	if sender {
		if r := d.Request; r != nil && !OffersVersion1(r.ProtocolVersion) {
			return fieldError("Dialogue.Request.ProtocolVersion", ErrUnsupportedProtocolVersion)
		}
		if r := d.Unidirectional; r != nil && !OffersVersion1(r.ProtocolVersion) {
			return fieldError("Dialogue.Unidirectional.ProtocolVersion", ErrUnsupportedProtocolVersion)
		}
		// Q.774 clause 3.2.2.1 excludes user information only when sending provider ABRT.
		if r := d.Abort; r != nil && r.AbortSource.BigInt().Cmp(bigOne) == 0 && r.UserInformation != nil {
			return fieldError("Dialogue.Abort.UserInformation", ErrUnexpectedUserInformation)
		}
	}
	return nil
}

// onlyVersion1 reports whether protocol-version is {version1}: bit 0 set and
// no other bit of the value set.
func onlyVersion1(v *runtime.BitString) bool {
	if v == nil {
		return true
	}
	if !OffersVersion1(v) {
		return false
	}
	for i := 1; i < v.BitLength && i/8 < len(v.Bytes); i++ {
		if v.Bytes[i/8]&(0x80>>(i%8)) != 0 {
			return false
		}
	}
	return true
}
