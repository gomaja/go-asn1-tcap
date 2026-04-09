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

// DefaultAcnPrefix represents the prefix for the Application Context Name (ACN).
var DefaultAcnPrefix = []uint64{0, 4, 0, 0, 1, 0}
