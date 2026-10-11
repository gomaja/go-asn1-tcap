package tcap

import wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"

// The dialogue portions below carry the field values that ITU-T Q.774
// (06/97) clause 3.2 prescribes for dialogue confirmation, refusal and abort.
// Put them in a message as any other Dialogue:
//
//	reply := &tcap.Continue{OTID: localID, DTID: begin.OTID, Dialogue: tcap.NewAcceptDialogue(acn, nil)}
//	refusal := &tcap.Abort{DTID: begin.OTID, Dialogue: tcap.NewRejectDialogue(acn, diagnostic, nil)}

// NewAcceptDialogue returns the AARE that accepts a dialogue, for the first
// backward Continue or an End answering a Begin (Q.774 clause 3.2.1,
// "Dialogue confirmation" and "Dialogue end"): protocol-version {version1},
// the given application context name, result accepted, result-source-
// diagnostic dialogue-service-user null. A nil userInformation omits the
// field.
func NewAcceptDialogue(applicationContextName OID, userInformation []External) *Dialogue {
	diagnostic := wire.AssociateSourceDiagnosticDialogueServiceUserValueNullValue()
	return &Dialogue{Response: &AARE{ProtocolVersion: ProtocolVersion1(), ApplicationContextName: applicationContextName,
		Result: wire.AssociateResultAcceptedValue(), ResultSourceDiagnostic: ResultSourceDiagnostic{DialogueServiceUser: &diagnostic}, UserInformation: cloneExternals(userInformation)}}
}

// NewRejectDialogue returns the AARE that refuses a dialogue, for an Abort
// answering a Begin: protocol-version {version1}, the given application
// context name, result reject-permanent and the given diagnostic.
//
// Q.774 clause 3.2.1 uses dialogue-service-user
// application-context-name-not-supported when the proposed application
// context is not supported (the application context name is then the one the
// responder offers instead), and dialogue-service-user null or
// no-reason-given when the dialogue is refused for another reason. Q.774
// clause 3.2.3 uses dialogue-service-provider no-common-dialogue-portion,
// with the received application context name and no user information, when
// the request does not offer protocol version 1.
func NewRejectDialogue(applicationContextName OID, diagnostic ResultSourceDiagnostic, userInformation []External) *Dialogue {
	return &Dialogue{Response: &AARE{ProtocolVersion: ProtocolVersion1(), ApplicationContextName: applicationContextName,
		Result: wire.AssociateResultRejectPermanentValue(), ResultSourceDiagnostic: cloneDiagnostic(diagnostic), UserInformation: cloneExternals(userInformation)}}
}

// NewUserAbortDialogue returns the ABRT with which a TC-user aborts a
// dialogue: abort-source dialogue-service-user and the given user information
// (Q.774 clause 3.2.2.1). A nil userInformation omits the field.
func NewUserAbortDialogue(userInformation []External) *Dialogue {
	return &Dialogue{Abort: &ABRT{AbortSource: wire.ABRTSourceDialogueServiceUserValue(), UserInformation: cloneExternals(userInformation)}}
}

// NewProviderAbortDialogue returns the ABRT with which the dialogue service
// provider aborts a dialogue after receiving an incorrect dialogue portion:
// abort-source dialogue-service-provider and no user information (Q.774
// clause 3.2.2.1).
func NewProviderAbortDialogue() *Dialogue {
	return &Dialogue{Abort: &ABRT{AbortSource: wire.ABRTSourceDialogueServiceProviderValue()}}
}
