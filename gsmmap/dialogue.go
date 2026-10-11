package gsmmap

import "github.com/gomaja/go-asn1-tcap"

// DialogueAS is the abstract syntax name of the MAP dialogue PDUs
// (map-DialoguePDU, version 1) that MAP carries as user information in the
// dialogue portion: 3GPP TS 29.002 V19.1.0 clause 17.4, module
// MAP-DialogueInformation.
const DialogueAS tcap.OID = "0.4.0.0.1.1.1.1" // map-DialogueAS
