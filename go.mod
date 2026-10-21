module github.com/gomaja/go-asn1-tcap

go 1.26.9

require github.com/gomaja/go-asn1 v0.0.0-20261021055857-7b9d01bda740

retract (
	v1.0.2 // Published only to retract v1.0.0 and v1.0.1; depend on the main branch.
	v1.0.1 // Predates the main-only API; depend on the main branch.
	v1.0.0 // Predates the main-only API; depend on the main branch.
)
