package tcap

// Transaction ID constraints per ITU-T Q.773.
const (
	MinTransactionIDLength = 1
	MaxTransactionIDLength = 4
)

// Invoke ID constraints (signed 8-bit integer range).
const (
	MinInvokeID = -128
	MaxInvokeID = 127
)

// Protocol version for TCAP dialogue.
const (
	DefaultProtocolVersion = 0x80 // 128 decimal
)

// defaultAcnPrefix is the base OID prefix for Application Context Names (ACN).
var defaultAcnPrefix = []uint64{0, 4, 0, 0, 1, 0}

// DefaultAcnPrefix returns a copy of the ACN OID prefix: 0.4.0.0.1.0
func DefaultAcnPrefix() []uint64 {
	return append([]uint64(nil), defaultAcnPrefix...)
}
