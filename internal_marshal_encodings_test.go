package tcap

import "reflect"

// Q.773 (06/97) clause 3.2.1 gives an absent protocol-version its default.
func internalEffectiveDialogue(d *Dialogue) *Dialogue {
	if d == nil {
		return nil
	}
	copy := *d
	if d.Request != nil {
		r := *d.Request
		copy.Request = &r
		if onlyVersion1(r.ProtocolVersion) {
			r.ProtocolVersion = nil
		}
	}
	if d.Response != nil {
		r := *d.Response
		copy.Response = &r
		if onlyVersion1(r.ProtocolVersion) {
			r.ProtocolVersion = nil
		}
	}
	if d.Unidirectional != nil {
		r := *d.Unidirectional
		copy.Unidirectional = &r
		if onlyVersion1(r.ProtocolVersion) {
			r.ProtocolVersion = nil
		}
	}
	return &copy
}

func internalEffectiveMessage(m Message) Message {
	switch m := m.(type) {
	case *Begin:
		c := *m
		c.Dialogue = internalEffectiveDialogue(m.Dialogue)
		return &c
	case *Continue:
		c := *m
		c.Dialogue = internalEffectiveDialogue(m.Dialogue)
		return &c
	case *End:
		c := *m
		c.Dialogue = internalEffectiveDialogue(m.Dialogue)
		return &c
	case *Abort:
		c := *m
		c.Dialogue = internalEffectiveDialogue(m.Dialogue)
		return &c
	case *Unidirectional:
		c := *m
		c.Dialogue = internalEffectiveDialogue(m.Dialogue)
		return &c
	}
	return m
}

func internalSameMessage(a, b Message) bool {
	return reflect.DeepEqual(internalEffectiveMessage(a), internalEffectiveMessage(b))
}

// Marshal omits DEFAULT {version1}: https://github.com/gomaja/go-asn1/issues/164.
var internalCorpusMarshalEncodings = map[string]string{
	"begin-aarq-invoke":                      "62334804010203046b1a2818060700118605010101a00d600ba1090607040000010014036c0fa10d02010102012d30050403010203",
	"begin-aarq-map-open":                    "625e4804010203046b392837060700118605010101a02c602aa109060704000001001403be1d281b060704000001010101a010a00e800591214365f7810591769810f26c1ba11902010102012d3011800591214365f78101ff820591769810f2",
	"continue-first-backward-aare-result":    "65464804010203044904050607086b262824060700118605010101a0196117a109060704000001001403a203020100a305a1030201006c10a20e020101300902012d30040402aabb",
	"abort-aare-map-version-fallback":        "672e4904050607086b262824060700118605010101a0196117a109060704000001001402a203020101a305a103020102",
	"abort-aare-provider-no-common-dialogue": "672e4904050607086b262824060700118605010101a0196117a109060704000001001403a203020101a305a203020102",
	"unidirectional-audt-invoke":             "612d6b1a2818060700118605010201a00d600ba1090607040000010014036c0fa10d02010102012d30050403010203",
	"begin-aarq-no-components":               "62224804010203046b1a2818060700118605010101a00d600ba109060704000001001403",
}

// Marshal omits DEFAULT {version1}: https://github.com/gomaja/go-asn1/issues/164.
var internalCaptureMarshalEncodings = map[string]string{
	"Begin SRI SM":                         "62454804004734a86b1a2818060700118605010101a00d600ba1090607040000010014036c21a11f02010002012d3017800891328490507608f38101ff820891328490000005f7",
	"Begin otid long message":              "62224804008bd0406b1a2818060700118605010101a00d600ba109060704000001001903",
	"Begin invoke reportSM-DeliveryStatus": "6243480403c940ec6b1a2818060700118605010101a00d600ba1090607040000010014036c1fa11d02010002012f30150407910201068163280407916427417901f00a0101",
	"Begin invoke mt-forwardSM":            "6281b4480403c93f576b1a2818060700118605010101a00d600ba1090607040000010019036c818fa1818c02010002012c308183800874020110261338f38407916427417901f0046e040bd0536152e85c0200004221824143220068c1f1f85d77d341582c360693c16c322c168bc5828865719a5e2683ee693a1ad4b44a4136180ce68281de6e900cf78ac95e321a0b449587dd7373592e2f9341d4372838bd06a9c82ca8e99a2689c8a00b34152641cd309b9cb697e7",
	"End SRI SM response":                  "6451490402b0d1c66b262824060700118605010101a0196117a109060704000001001402a203020100a305a1030201006c21a21f020100301a02012d3015040806031128951337f4a009810791126316002012",
	"Abort DTID version mismatch":          "672e490402b0d1c46b262824060700118605010101a0196117a109060704000001001402a203020101a305a103020102",
}
