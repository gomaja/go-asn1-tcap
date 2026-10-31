package tcap_test

import (
	"encoding/hex"
	"errors"
	"testing"

	tcap "github.com/gomaja/go-asn1-tcap"
)

// These vectors check the Q.773 (06/97) Table 12 cause and Portion of Parse
// failures across message types, tolerance and decode limits.
type parseAbortCauseVectorOutcome struct {
	success bool
	portion tcap.Portion
	cause   int64
	ok      bool
}

type parseAbortCauseVector struct {
	name     string
	hex      string
	tolerant bool
	limits   tcap.DecodeLimits // Zero fields retain defaults.
	want     parseAbortCauseVectorOutcome
	ref      string // One-line specification reference for this vector.
}

func parseAbortCauseVectors() []parseAbortCauseVector {
	success := parseAbortCauseVectorOutcome{success: true}
	unknown := parseAbortCauseVectorOutcome{portion: tcap.PortionTransaction, cause: tcap.PAbortCauseUnrecognizedMessageType, ok: true}
	badBER := parseAbortCauseVectorOutcome{portion: tcap.PortionTransaction, cause: tcap.PAbortCauseBadlyFormattedTransactionPortion, ok: true}
	incorrect := parseAbortCauseVectorOutcome{portion: tcap.PortionTransaction, cause: tcap.PAbortCauseIncorrectTransactionPortion, ok: true}
	resource := parseAbortCauseVectorOutcome{portion: tcap.PortionTransaction, cause: tcap.PAbortCauseResourceLimitation, ok: true}
	dialogue := parseAbortCauseVectorOutcome{portion: tcap.PortionDialogue}
	component := parseAbortCauseVectorOutcome{portion: tcap.PortionComponent}
	return []parseAbortCauseVector{
		{
			name: "unidirectional valid", hex: "610a6c08a10602010102012d",
			want: success, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "unidirectional truncated", hex: "610a6c08a1060201010201",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "unidirectional trailing octet", hex: "610a6c08a10602010102012d00",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "unidirectional second message", hex: "610a6c08a10602010102012d610a6c08a10602010102012d",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "unidirectional extra null inside", hex: "610c6c08a10602010102012d0500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "unidirectional codec depth limit", hex: "610a6c08a10602010102012d",
			limits: tcap.DecodeLimits{MaxDepth: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unidirectional codec elements limit", hex: "610a6c08a10602010102012d",
			limits: tcap.DecodeLimits{MaxElements: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unidirectional codec work limit", hex: "610a6c08a10602010102012d",
			limits: tcap.DecodeLimits{MaxWork: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin valid", hex: "6203480101",
			want: success, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin truncated", hex: "62034801",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin trailing octet", hex: "620348010100",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin second message", hex: "62034801016203480101",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra null inside", hex: "62054801010500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin codec depth limit", hex: "620d4801016c08a10602010102012d",
			limits: tcap.DecodeLimits{MaxDepth: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin codec elements limit", hex: "6203480101",
			limits: tcap.DecodeLimits{MaxElements: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin codec work limit", hex: "6203480101",
			limits: tcap.DecodeLimits{MaxWork: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "continue valid", hex: "6506480101490102",
			want: success, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "continue truncated", hex: "65064801014901",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue trailing octet", hex: "650648010149010200",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue second message", hex: "65064801014901026506480101490102",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue extra null inside", hex: "65084801014901020500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "continue codec depth limit", hex: "65104801014901026c08a10602010102012d",
			limits: tcap.DecodeLimits{MaxDepth: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "continue codec elements limit", hex: "6506480101490102",
			limits: tcap.DecodeLimits{MaxElements: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "continue codec work limit", hex: "6506480101490102",
			limits: tcap.DecodeLimits{MaxWork: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "end valid", hex: "6403490102",
			want: success, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "end truncated", hex: "64034901",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end trailing octet", hex: "640349010200",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end second message", hex: "64034901026403490102",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end extra null inside", hex: "64054901020500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "end codec depth limit", hex: "640d4901026c08a10602010102012d",
			limits: tcap.DecodeLimits{MaxDepth: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "end codec elements limit", hex: "6403490102",
			limits: tcap.DecodeLimits{MaxElements: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "end codec work limit", hex: "6403490102",
			limits: tcap.DecodeLimits{MaxWork: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "abort valid", hex: "67064901024a0100",
			want: success, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort truncated", hex: "67064901024a01",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort trailing octet", hex: "67064901024a010000",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort second message", hex: "67064901024a010067064901024a0100",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort extra null inside", hex: "67084901024a01000500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort codec depth limit", hex: "670c4901026b07280506012a8100",
			limits: tcap.DecodeLimits{MaxDepth: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "abort codec elements limit", hex: "67064901024a0100",
			limits: tcap.DecodeLimits{MaxElements: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "abort codec work limit", hex: "67064901024a0100",
			limits: tcap.DecodeLimits{MaxWork: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin declared length exceeds input", hex: "620648027f016c",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin OTID followed by NULL", hex: "620648027f010500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A; Q.774 (06/97) clause 3.2.3",
		},
		{
			name: "begin declared length exceeds input tolerant", hex: "620648027f016c",
			tolerant: true,
			want:     badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin OTID followed by NULL tolerant", hex: "620648027f010500",
			tolerant: true,
			want:     incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "reserved 3", hex: "6300",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "reserved 6", hex: "6600",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "universal sequence", hex: "3000",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "context specific", hex: "a200",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "high tag 32", hex: "7f2000",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "high tag 128", hex: "7f810000",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unknown without length", hex: "66",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unknown bad length", hex: "668201",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unknown primitive indefinite", hex: "46800000",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unidirectional primitive message tag", hex: "410a6c08a10602010102012d",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin primitive message tag", hex: "4203480101",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "continue primitive message tag", hex: "4506480101490102",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "end primitive message tag", hex: "4403490102",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "abort primitive message tag", hex: "47064901024a0100",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unknown tag maxdepth limit", hex: "660730053003050100",
			limits: tcap.DecodeLimits{MaxDepth: 1},
			want:   unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unknown tag maxelements limit", hex: "660730053003050100",
			limits: tcap.DecodeLimits{MaxElements: 1},
			want:   unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unknown tag maxwork limit", hex: "660730053003050100",
			limits: tcap.DecodeLimits{MaxWork: 1},
			want:   unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "empty", hex: "",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "tag only", hex: "62",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "truncated high tag", hex: "7f",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "truncated high tag continuation", hex: "7f81",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "truncated high tag long", hex: "7f8180",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "unterminated length", hex: "6282",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "truncated length octets", hex: "628201",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "reserved length octet", hex: "62ff",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin declared shorter", hex: "6202480101",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra malformed child", hex: "620448010105",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin primitive indefinite tid", hex: "620748800100000500",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "eoc at root", hex: "0000",
			want: unknown, ref: "Q.773 (06/97) clause 4.2.1.2, Table 8; Q.774 (06/97) Figure A.3",
		},
		{
			name: "unidirectional indefinite valid", hex: "61806c08a10602010102012d0000",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "unidirectional indefinite missing eoc", hex: "61806c08a10602010102012d",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin indefinite valid", hex: "62804801010000",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin indefinite missing eoc", hex: "6280480101",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue indefinite valid", hex: "65804801014901020000",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue indefinite missing eoc", hex: "6580480101490102",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end indefinite valid", hex: "64804901020000",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end indefinite missing eoc", hex: "6480490102",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort indefinite valid", hex: "67804901024a01000000",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort indefinite missing eoc", hex: "67804901024a0100",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin eoc in definite contents", hex: "62054801010000",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin eoc before tid", hex: "62800000480101",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin indefinite trailing eoc", hex: "628048010100000000",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin component indefinite valid", hex: "620f4801016c80a10602010102012d0000",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin component indefinite missing eoc", hex: "620d4801016c80a10602010102012d",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin component portion truncated", hex: "62074801016c03a100",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin component portion wrong tag", hex: "620d4801016d08a10602010102012d",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin component portion primitive", hex: "620d4801014c08a10602010102012d",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1; Q.773 (06/97) Annex A",
		},
		{
			name: "unidirectional long length below 128 strict", hex: "61810a6c08a10602010102012d",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "unidirectional long length below 128 tolerant", hex: "61810a6c08a10602010102012d",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "unidirectional nonminimal length strict", hex: "6182000a6c08a10602010102012d",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "unidirectional nonminimal length tolerant", hex: "6182000a6c08a10602010102012d",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin long length below 128 strict", hex: "628103480101",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin long length below 128 tolerant", hex: "628103480101",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin nonminimal length strict", hex: "62820003480101",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin nonminimal length tolerant", hex: "62820003480101",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue long length below 128 strict", hex: "658106480101490102",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue long length below 128 tolerant", hex: "658106480101490102",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue nonminimal length strict", hex: "65820006480101490102",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "continue nonminimal length tolerant", hex: "65820006480101490102",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end long length below 128 strict", hex: "648103490102",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end long length below 128 tolerant", hex: "648103490102",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end nonminimal length strict", hex: "64820003490102",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "end nonminimal length tolerant", hex: "64820003490102",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort long length below 128 strict", hex: "6781064901024a0100",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort long length below 128 tolerant", hex: "6781064901024a0100",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort nonminimal length strict", hex: "678200064901024a0100",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "abort nonminimal length tolerant", hex: "678200064901024a0100",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin long length and extra inside strict", hex: "6281054801010500",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1; Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin long length and extra inside tolerant", hex: "6281054801010500",
			tolerant: true,
			want:     incorrect, ref: "Q.773 (06/97) clause 4.1.1; Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin constructed tid strict", hex: "62056803040101",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin constructed tid tolerant", hex: "62056803040101",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "continue constructed dtid strict", hex: "65084801016903040102",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "continue constructed dtid tolerant", hex: "65084801016903040102",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin constructed indefinite tid strict", hex: "620768800401010000",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin constructed indefinite tid tolerant", hex: "620768800401010000",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin constructed tid and extra inside strict", hex: "620768030401010500",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A; Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin constructed tid and extra inside tolerant", hex: "620768030401010500",
			tolerant: true,
			want:     incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A; Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin tid long length strict", hex: "620448810101",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin tid long length tolerant", hex: "620448810101",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin tid nonminimal length strict", hex: "62054882000101",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin tid nonminimal length tolerant", hex: "62054882000101",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin constructed tid wrong fragment strict", hex: "62056803020101",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin constructed tid wrong fragment tolerant", hex: "62056803020101",
			tolerant: true,
			want:     badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin empty tid strict", hex: "62024800",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin empty tid tolerant", hex: "62024800",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin five octets tid strict", hex: "620748050102030405",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin five octets tid tolerant", hex: "620748050102030405",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "continue empty tid strict", hex: "65054800490102",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "continue empty tid tolerant", hex: "65054800490102",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "continue five octets tid strict", hex: "650a48050102030405490102",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "continue five octets tid tolerant", hex: "650a48050102030405490102",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "end empty tid strict", hex: "64024900",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "end empty tid tolerant", hex: "64024900",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "end five octets tid strict", hex: "640749050102030405",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "end five octets tid tolerant", hex: "640749050102030405",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "abort empty tid strict", hex: "670549004a0100",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "abort empty tid tolerant", hex: "670549004a0100",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "abort five octets tid strict", hex: "670a490501020304054a0100",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "abort five octets tid tolerant", hex: "670a490501020304054a0100",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "continue empty dtid strict", hex: "65054801014900",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "continue empty dtid tolerant", hex: "65054801014900",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.3, Tables 9 and 10 and Annex A",
		},
		{
			name: "begin empty tid and invalid null strict", hex: "620548000501ff",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin empty tid and invalid null tolerant", hex: "620548000501ff",
			tolerant: true,
			want:     badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin five octet tid and truncated child strict", hex: "6208480501020304056c",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin five octet tid and truncated child tolerant", hex: "6208480501020304056c",
			tolerant: true,
			want:     badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin missing otid", hex: "6200",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin dtid instead of otid", hex: "6203490102",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin two otids", hex: "6206480101480102",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin otid then dtid", hex: "6206480101490102",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin component before otid", hex: "620d6c08a10602010102012d480101",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "continue missing otid", hex: "6503490102",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "continue missing dtid", hex: "6503480101",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "continue no ids", hex: "6500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "continue ids swapped", hex: "6506490102480101",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "continue repeated dtid", hex: "6509480101490102490103",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "end otid instead of dtid", hex: "6403480101",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "end dtid then otid", hex: "6406490102480101",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "end missing dtid", hex: "6400",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "unidirectional with tid", hex: "610d4801016c08a10602010102012d",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "unidirectional without components", hex: "6100",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort missing dtid", hex: "67034a0100",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort wrong tid", hex: "67064801014a0100",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort repeated cause", hex: "67094901024a01004a0102",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort cause before dtid", hex: "67064a0100490102",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort with components", hex: "670d4901026c08a10602010102012d",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin two component portions", hex: "62174801016c08a10602010102012d6c08a10602010102012d",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort cause empty integer strict", hex: "67054901024a00",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause empty integer tolerant", hex: "67054901024a00",
			tolerant: true,
			want:     badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause nonminimal positive strict", hex: "67074901024a020000",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause nonminimal positive tolerant", hex: "67074901024a020000",
			tolerant: true,
			want:     badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause nonminimal negative strict", hex: "67074901024a02ffff",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause nonminimal negative tolerant", hex: "67074901024a02ffff",
			tolerant: true,
			want:     badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause 200 strict", hex: "67074901024a0200c8",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause 200 tolerant", hex: "67074901024a0200c8",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause negative strict", hex: "67064901024a01ff",
			want: incorrect, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause negative tolerant", hex: "67064901024a01ff",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort cause 127", hex: "67064901024a017f",
			want: success, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "abort without reason", hex: "6703490102",
			want: success, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort cause and dialogue", hex: "670f4901024a01006b07280506012a8100",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "abort cause constructed integer", hex: "67084901026a03020100",
			want: badBER, ref: "Q.773 (06/97) clauses 4.1.1 and 4.2.1.4, Tables 11 and 12 and Annex A",
		},
		{
			name: "begin extra invalid null", hex: "62064801010501ff",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra empty integer", hex: "62054801010200",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra invalid boolean", hex: "620748010101020000",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra constructed null", hex: "62054801012500",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra primitive sequence", hex: "62054801011000",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra malformed child tag", hex: "62054801011f81",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra unexpected valid integer", hex: "6206480101020101",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin malformed dialogue own portion", hex: "62054801016b00",
			want: dialogue, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5",
		},
		{
			name: "end malformed dialogue own portion", hex: "64054901026b00",
			want: dialogue, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5",
		},
		{
			name: "begin malformed component own portion", hex: "620a4801016c05a103020101",
			want: component, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5",
		},
		{
			name: "continue malformed component own portion", hex: "650d4801014901026c05a103020101",
			want: component, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5",
		},
		{
			name: "begin component unknown tag own portion", hex: "62074801016c02a500",
			want: component, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5",
		},
		{
			name: "unidirectional malformed component own portion", hex: "61076c05a103020101",
			want: component, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5",
		},
		{
			name: "begin bad component and extra null", hex: "620c4801016c05a1030201010500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "continue missing dtid and bad component", hex: "650a4801016c05a103020101",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin malformed component and trailing octet", hex: "620a4801016c05a10302010100",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin bad dialogue and trailing octet", hex: "62054801016b0000",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin wrong layout and malformed component", hex: "620b4901026c06a104020201",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin component empty integer own portion strict", hex: "620c4801016c07a105020002012d",
			want: component, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5; Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin component empty integer own portion tolerant", hex: "620c4801016c07a105020002012d",
			tolerant: true,
			want:     component, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5; Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin dialogue empty integer own portion strict", hex: "62094801016b0428020200",
			want: dialogue, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5; Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin dialogue empty integer own portion tolerant", hex: "62094801016b0428020200",
			tolerant: true,
			want:     dialogue, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5; Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin extra children maxwork limit", hex: "62074801014f004e00",
			limits: tcap.DecodeLimits{MaxWork: 8},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin extra children maxelements limit", hex: "62074801014f004e00",
			limits: tcap.DecodeLimits{MaxElements: 2},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin inspection only maxwork limit", hex: "620448010105",
			limits: tcap.DecodeLimits{MaxWork: 5},
			want:   badBER, ref: "Q.773 (06/97) clause 4.1.1; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin inspection only maxelements limit", hex: "620448010105",
			limits: tcap.DecodeLimits{MaxElements: 2},
			want:   badBER, ref: "Q.773 (06/97) clause 4.1.1; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin truncated but work limit first", hex: "620648027f016c",
			limits: tcap.DecodeLimits{MaxWork: 1},
			want:   resource, ref: "Q.773 (06/97) Table 12; Q.774 (06/97) Figure A.3",
		},
		{
			name: "begin minimal long length 137", hex: "6281894801016c8183a1818002010102012d0478000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin nonminimal long length 137 strict", hex: "628200894801016c8183a1818002010102012d0478000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin nonminimal long length 137 tolerant", hex: "628200894801016c8183a1818002010102012d0478000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin constructed protocol version own portion strict", hex: "621f4801016b1a2818060700118605010101a00d600ba00403020780a10306012a",
			want: dialogue, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5; Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin constructed protocol version own portion tolerant", hex: "621f4801016b1a2818060700118605010101a00d600ba00403020780a10306012a",
			tolerant: true,
			want:     success, ref: "Q.773 (06/97) clause 4; Q.774 (06/97) clauses 3.2.2.1 and 3.2.2.2, Table 5; Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin constructed protocol version after empty OTID strict", hex: "621e48006b1a2818060700118605010101a00d600ba00403020780a10306012a",
			want: badBER, ref: "Q.773 (06/97) clause 4.1.1; ITU-T X.690 (02/2021) clause 8.14.4",
		},
		// After a DTID where the OTID belongs, the dialogue portion is out of
		// its place too, and the IMPLICIT protocol-version gives no type to
		// check (ITU-T X.690 (02/2021) clause 8.14.4).
		{
			name: "begin constructed protocol version wrong transaction strict", hex: "621f4901026b1a2818060700118605010101a00d600ba00403020780a10306012a",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A; ITU-T X.690 (02/2021) clause 8.14.4",
		},
		{
			name: "begin constructed protocol version wrong transaction tolerant", hex: "621f4901026b1a2818060700118605010101a00d600ba00403020780a10306012a",
			tolerant: true,
			want:     incorrect, ref: "Q.773 (06/97) clause 4.1.1; Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin user parameter constructed octet string", hex: "62124801016c0da10b02010102012d24030401ff",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin user parameter constructed octet string extra null", hex: "62144801016c0da10b02010102012d24030401ff0500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
		{
			name: "begin user parameter long octet string length", hex: "62114801016c0ca10a02010102012d048101ff",
			want: success, ref: "Q.773 (06/97) clause 4.1.1",
		},
		{
			name: "begin user parameter long octet string length extra null", hex: "62134801016c0ca10a02010102012d048101ff0500",
			want: incorrect, ref: "Q.773 (06/97) clauses 3.1 and 4.2.1.1, Tables 3 to 7 and Annex A",
		},
	}
}

func TestParsePAbortCauseVectors(t *testing.T) {
	for _, v := range parseAbortCauseVectors() {
		t.Run(v.name, func(t *testing.T) {
			raw, err := hex.DecodeString(v.hex)
			if err != nil {
				t.Fatalf("invalid fixture hex: %v", err)
			}
			var opts []tcap.ParseOption
			if v.tolerant {
				// Each vector and each run gets a fresh log.
				opts = append(opts, tcap.WithTolerance(&tcap.ViolationLog{}))
			}
			if v.limits != (tcap.DecodeLimits{}) {
				opts = append(opts, tcap.WithDecodeLimits(v.limits))
			}
			message, err := tcap.Parse(raw, opts...)
			if v.want.success {
				if err != nil || message == nil {
					t.Fatalf("Parse = %T, %v; want success (%s)", message, err, v.ref)
				}
				return
			}
			var pe *tcap.ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse = %T, %v; want *ParseError (%s)", message, err, v.ref)
			}
			if message != nil {
				t.Errorf("Parse returned message %T with error", message)
			}
			if pe.Portion != v.want.portion {
				t.Errorf("Portion = %q; want %q (%s)", pe.Portion, v.want.portion, v.ref)
			}
			c, ok := pe.PAbortCause()
			if ok != v.want.ok {
				t.Errorf("PAbortCause ok = %v; want %v (%s)", ok, v.want.ok, v.ref)
			}
			if !v.want.ok {
				// The cause value is unspecified when ok is false.
				return
			}
			got, fits := c.AsInt64()
			if !fits || got != v.want.cause {
				t.Errorf("PAbortCause = (%v, fits=%v, ok=%v); want (%d, true) (%s)", got, fits, ok, v.want.cause, v.ref)
			}
		})
	}
}
