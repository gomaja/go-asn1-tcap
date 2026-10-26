package tcap_test

import (
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
)

type publicNamedInteger interface {
	AsInt64() (int64, bool)
	Name() (string, bool)
}

func TestPublicNamedNumbers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		number int64
		value  publicNamedInteger
		label  string
	}{
		{"PAbortCauseUnrecognizedMessageType", tcap.PAbortCauseUnrecognizedMessageType, tcap.NewPAbortCause(tcap.PAbortCauseUnrecognizedMessageType), "unrecognizedMessageType"},
		{"PAbortCauseUnrecognizedTransactionID", tcap.PAbortCauseUnrecognizedTransactionID, tcap.NewPAbortCause(tcap.PAbortCauseUnrecognizedTransactionID), "unrecognizedTransactionID"},
		{"PAbortCauseBadlyFormattedTransactionPortion", tcap.PAbortCauseBadlyFormattedTransactionPortion, tcap.NewPAbortCause(tcap.PAbortCauseBadlyFormattedTransactionPortion), "badlyFormattedTransactionPortion"},
		{"PAbortCauseIncorrectTransactionPortion", tcap.PAbortCauseIncorrectTransactionPortion, tcap.NewPAbortCause(tcap.PAbortCauseIncorrectTransactionPortion), "incorrectTransactionPortion"},
		{"PAbortCauseResourceLimitation", tcap.PAbortCauseResourceLimitation, tcap.NewPAbortCause(tcap.PAbortCauseResourceLimitation), "resourceLimitation"},
		{"AssociateResultAccepted", tcap.AssociateResultAccepted, tcap.NewAssociateResult(tcap.AssociateResultAccepted), "accepted"},
		{"AssociateResultRejectPermanent", tcap.AssociateResultRejectPermanent, tcap.NewAssociateResult(tcap.AssociateResultRejectPermanent), "reject-permanent"},
		{"DialogueServiceUserNull", tcap.DialogueServiceUserNull, tcap.NewDialogueServiceUserDiagnostic(tcap.DialogueServiceUserNull), "null"},
		{"DialogueServiceUserNoReasonGiven", tcap.DialogueServiceUserNoReasonGiven, tcap.NewDialogueServiceUserDiagnostic(tcap.DialogueServiceUserNoReasonGiven), "no-reason-given"},
		{"DialogueServiceUserApplicationContextNameNotSupported", tcap.DialogueServiceUserApplicationContextNameNotSupported, tcap.NewDialogueServiceUserDiagnostic(tcap.DialogueServiceUserApplicationContextNameNotSupported), "application-context-name-not-supported"},
		{"DialogueServiceProviderNull", tcap.DialogueServiceProviderNull, tcap.NewDialogueServiceProviderDiagnostic(tcap.DialogueServiceProviderNull), "null"},
		{"DialogueServiceProviderNoReasonGiven", tcap.DialogueServiceProviderNoReasonGiven, tcap.NewDialogueServiceProviderDiagnostic(tcap.DialogueServiceProviderNoReasonGiven), "no-reason-given"},
		{"DialogueServiceProviderNoCommonDialoguePortion", tcap.DialogueServiceProviderNoCommonDialoguePortion, tcap.NewDialogueServiceProviderDiagnostic(tcap.DialogueServiceProviderNoCommonDialoguePortion), "no-common-dialogue-portion"},
		{"ABRTSourceDialogueServiceUser", tcap.ABRTSourceDialogueServiceUser, tcap.NewABRTSource(tcap.ABRTSourceDialogueServiceUser), "dialogue-service-user"},
		{"ABRTSourceDialogueServiceProvider", tcap.ABRTSourceDialogueServiceProvider, tcap.NewABRTSource(tcap.ABRTSourceDialogueServiceProvider), "dialogue-service-provider"},
		{"GeneralProblemUnrecognizedPDU", tcap.GeneralProblemUnrecognizedPDU, tcap.NewGeneralProblem(tcap.GeneralProblemUnrecognizedPDU), "unrecognizedPDU"},
		{"GeneralProblemMistypedPDU", tcap.GeneralProblemMistypedPDU, tcap.NewGeneralProblem(tcap.GeneralProblemMistypedPDU), "mistypedPDU"},
		{"GeneralProblemBadlyStructuredPDU", tcap.GeneralProblemBadlyStructuredPDU, tcap.NewGeneralProblem(tcap.GeneralProblemBadlyStructuredPDU), "badlyStructuredPDU"},
		{"InvokeProblemDuplicateInvocation", tcap.InvokeProblemDuplicateInvocation, tcap.NewInvokeProblem(tcap.InvokeProblemDuplicateInvocation), "duplicateInvocation"},
		{"InvokeProblemUnrecognizedOperation", tcap.InvokeProblemUnrecognizedOperation, tcap.NewInvokeProblem(tcap.InvokeProblemUnrecognizedOperation), "unrecognizedOperation"},
		{"InvokeProblemMistypedArgument", tcap.InvokeProblemMistypedArgument, tcap.NewInvokeProblem(tcap.InvokeProblemMistypedArgument), "mistypedArgument"},
		{"InvokeProblemResourceLimitation", tcap.InvokeProblemResourceLimitation, tcap.NewInvokeProblem(tcap.InvokeProblemResourceLimitation), "resourceLimitation"},
		{"InvokeProblemReleaseInProgress", tcap.InvokeProblemReleaseInProgress, tcap.NewInvokeProblem(tcap.InvokeProblemReleaseInProgress), "releaseInProgress"},
		{"InvokeProblemUnrecognizedLinkedId", tcap.InvokeProblemUnrecognizedLinkedId, tcap.NewInvokeProblem(tcap.InvokeProblemUnrecognizedLinkedId), "unrecognizedLinkedId"},
		{"InvokeProblemLinkedResponseUnexpected", tcap.InvokeProblemLinkedResponseUnexpected, tcap.NewInvokeProblem(tcap.InvokeProblemLinkedResponseUnexpected), "linkedResponseUnexpected"},
		{"InvokeProblemUnexpectedLinkedOperation", tcap.InvokeProblemUnexpectedLinkedOperation, tcap.NewInvokeProblem(tcap.InvokeProblemUnexpectedLinkedOperation), "unexpectedLinkedOperation"},
		{"ReturnResultProblemUnrecognizedInvocation", tcap.ReturnResultProblemUnrecognizedInvocation, tcap.NewReturnResultProblem(tcap.ReturnResultProblemUnrecognizedInvocation), "unrecognizedInvocation"},
		{"ReturnResultProblemResultResponseUnexpected", tcap.ReturnResultProblemResultResponseUnexpected, tcap.NewReturnResultProblem(tcap.ReturnResultProblemResultResponseUnexpected), "resultResponseUnexpected"},
		{"ReturnResultProblemMistypedResult", tcap.ReturnResultProblemMistypedResult, tcap.NewReturnResultProblem(tcap.ReturnResultProblemMistypedResult), "mistypedResult"},
		{"ReturnErrorProblemUnrecognizedInvocation", tcap.ReturnErrorProblemUnrecognizedInvocation, tcap.NewReturnErrorProblem(tcap.ReturnErrorProblemUnrecognizedInvocation), "unrecognizedInvocation"},
		{"ReturnErrorProblemErrorResponseUnexpected", tcap.ReturnErrorProblemErrorResponseUnexpected, tcap.NewReturnErrorProblem(tcap.ReturnErrorProblemErrorResponseUnexpected), "errorResponseUnexpected"},
		{"ReturnErrorProblemUnrecognizedError", tcap.ReturnErrorProblemUnrecognizedError, tcap.NewReturnErrorProblem(tcap.ReturnErrorProblemUnrecognizedError), "unrecognizedError"},
		{"ReturnErrorProblemUnexpectedError", tcap.ReturnErrorProblemUnexpectedError, tcap.NewReturnErrorProblem(tcap.ReturnErrorProblemUnexpectedError), "unexpectedError"},
		{"ReturnErrorProblemMistypedParameter", tcap.ReturnErrorProblemMistypedParameter, tcap.NewReturnErrorProblem(tcap.ReturnErrorProblemMistypedParameter), "mistypedParameter"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, ok := tt.value.AsInt64(); !ok || got != tt.number {
				t.Fatalf("AsInt64 = %d, %v; want %d, true", got, ok, tt.number)
			}
			if got, ok := tt.value.Name(); !ok || got != tt.label {
				t.Fatalf("Name = %q, %v; want %q, true", got, ok, tt.label)
			}
		})
	}
}

// Assignment to int8 also checks that the INTEGER named numbers stay untyped.
const (
	_ int8 = tcap.PAbortCauseUnrecognizedMessageType
	_ int8 = tcap.PAbortCauseUnrecognizedTransactionID
	_ int8 = tcap.PAbortCauseBadlyFormattedTransactionPortion
	_ int8 = tcap.PAbortCauseIncorrectTransactionPortion
	_ int8 = tcap.PAbortCauseResourceLimitation
	_ int8 = tcap.AssociateResultAccepted
	_ int8 = tcap.AssociateResultRejectPermanent
	_ int8 = tcap.DialogueServiceUserNull
	_ int8 = tcap.DialogueServiceUserNoReasonGiven
	_ int8 = tcap.DialogueServiceUserApplicationContextNameNotSupported
	_ int8 = tcap.DialogueServiceProviderNull
	_ int8 = tcap.DialogueServiceProviderNoReasonGiven
	_ int8 = tcap.DialogueServiceProviderNoCommonDialoguePortion
	_ int8 = tcap.ABRTSourceDialogueServiceUser
	_ int8 = tcap.ABRTSourceDialogueServiceProvider
	_ int8 = tcap.GeneralProblemUnrecognizedPDU
	_ int8 = tcap.GeneralProblemMistypedPDU
	_ int8 = tcap.GeneralProblemBadlyStructuredPDU
	_ int8 = tcap.InvokeProblemDuplicateInvocation
	_ int8 = tcap.InvokeProblemUnrecognizedOperation
	_ int8 = tcap.InvokeProblemMistypedArgument
	_ int8 = tcap.InvokeProblemResourceLimitation
	_ int8 = tcap.InvokeProblemReleaseInProgress
	_ int8 = tcap.InvokeProblemUnrecognizedLinkedId
	_ int8 = tcap.InvokeProblemLinkedResponseUnexpected
	_ int8 = tcap.InvokeProblemUnexpectedLinkedOperation
	_ int8 = tcap.ReturnResultProblemUnrecognizedInvocation
	_ int8 = tcap.ReturnResultProblemResultResponseUnexpected
	_ int8 = tcap.ReturnResultProblemMistypedResult
	_ int8 = tcap.ReturnErrorProblemUnrecognizedInvocation
	_ int8 = tcap.ReturnErrorProblemErrorResponseUnexpected
	_ int8 = tcap.ReturnErrorProblemUnrecognizedError
	_ int8 = tcap.ReturnErrorProblemUnexpectedError
	_ int8 = tcap.ReturnErrorProblemMistypedParameter
)
