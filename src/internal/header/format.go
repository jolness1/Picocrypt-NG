// Package header handles Picocrypt volume header reading, writing, and authentication.
// This is AUDIT-CRITICAL code - changes here directly affect file format compatibility.
package header

import "Picocrypt-NG/internal/encoding"

// Version constants
const (
	CurrentVersion = "v2.09"
	MaxCommentLen  = 99999
)

// Header field sizes (before Reed-Solomon encoding)
const (
	SaltSize        = 16 // Argon2 salt
	HKDFSaltSize    = 32 // HKDF-SHA3 salt
	SerpentIVSize   = 16 // Serpent IV
	NonceSize       = 24 // XChaCha20 nonce
	KeyHashSize     = 64 // HMAC-SHA3-512 of header (v2) or SHA3-512(key) (v1)
	KeyfileHashSize = 32 // SHA3-256 of keyfile key
	AuthTagSize     = 64 // BLAKE2b or HMAC-SHA3 tag
)

// Header field sizes after Reed-Solomon encoding
const (
	VersionEncSize     = 15  // rs5: 5 -> 15
	CommentLenEncSize  = 15  // rs5: 5 -> 15
	FlagsEncSize       = 15  // rs5: 5 -> 15
	SaltEncSize        = 48  // rs16: 16 -> 48
	HKDFSaltEncSize    = 96  // rs32: 32 -> 96
	SerpentIVEncSize   = 48  // rs16: 16 -> 48
	NonceEncSize       = 72  // rs24: 24 -> 72
	KeyHashEncSize     = 192 // rs64: 64 -> 192
	KeyfileHashEncSize = 96  // rs32: 32 -> 96
	AuthTagEncSize     = 192 // rs64: 64 -> 192
)

// BaseHeaderSize is the header size without comments (789 bytes)
// Formula: 15 + 15 + 15 + 48 + 96 + 48 + 72 + 192 + 96 + 192 = 789
const BaseHeaderSize = VersionEncSize + CommentLenEncSize + FlagsEncSize +
	SaltEncSize + HKDFSaltEncSize + SerpentIVEncSize + NonceEncSize +
	KeyHashEncSize + KeyfileHashEncSize + AuthTagEncSize

// HeaderSize calculates total header size including encoded comments
func HeaderSize(commentsLen int) int {
	return BaseHeaderSize + commentsLen*3 // Each comment byte is rs1 encoded (1->3)
}

// Flags represents the boolean options stored in the volume header
type Flags struct {
	Paranoid       bool // flags[0]: Paranoid mode (8 Argon2 passes, HMAC-SHA3)
	UseKeyfiles    bool // flags[1]: Keyfiles were used for encryption
	KeyfileOrdered bool // flags[2]: Keyfile order matters
	ReedSolomon    bool // flags[3]: Full Reed-Solomon encoding on payload (derived from RSParityBytes)
	Padded         bool // flags[4]: Final block was padded (RS internals)

	// RSParityBytes is the number of Reed-Solomon parity bytes per RS128-DataSize block.
	// 0 means RS is disabled. When reading a header this is set to the exact parity value
	// stored during encryption (old volumes that stored a boolean 1 map to DefaultRS128ParityBytes).
	//
	// When writing (ToBytes), if ReedSolomon is true and RSParityBytes is 0 or equal to
	// DefaultRS128ParityBytes, flags[3] is written as 1 (the legacy sentinel) so that old
	// binaries can still read the volume. Custom parity values (2-127, excluding 8) are
	// written directly.
	RSParityBytes int
}

// ToBytes converts Flags to 5-byte slice for encoding.
//
// flags[3] encodes the RS parity setting:
//   - 0 = RS disabled
//   - 1 = RS enabled with default parity (backward-compatible with old binaries
//     that interpret flags[3] as a boolean)
//   - 2-127 = RS enabled with N custom parity bytes per RS128 data block
//
// When ReedSolomon is true and RSParityBytes is 0 or equal to
// DefaultRS128ParityBytes (8), flags[3] is written as 1 to preserve
// backward compatibility. Custom parity values are written directly.
// Value 1 is reserved as a legacy value and must never be used
// as an actual parity byte count.
func (f *Flags) ToBytes() []byte {
	b := make([]byte, 5)
	if f.Paranoid {
		b[0] = 1
	}
	if f.UseKeyfiles {
		b[1] = 1
	}
	if f.KeyfileOrdered {
		b[2] = 1
	}
	if f.ReedSolomon {
		parity := f.RSParityBytes
		if parity == 0 || parity == encoding.DefaultRS128ParityBytes {
			// Legacy encoding: write 1 so old binaries see "RS enabled"
			b[3] = 1
		} else {
			b[3] = byte(parity)
		}
	}
	if f.Padded {
		b[4] = 1
	}
	return b
}

// FlagsFromBytes parses a 5-byte slice into Flags.
//
// flags[3] encodes the RS parity byte count:
//   - 0 = RS disabled
//   - 1 = RS enabled with DefaultRS128ParityBytes; backward-compatible with old volumes
//     where flags[3] was a boolean (0=off, 1=on with default parity)
//   - 2-127 = RS enabled with N parity bytes per RS128 data block
func FlagsFromBytes(b []byte) Flags {
	if len(b) < 5 {
		return Flags{}
	}
	f := Flags{
		Paranoid:       b[0] == 1,
		UseKeyfiles:    b[1] == 1,
		KeyfileOrdered: b[2] == 1,
		Padded:         b[4] == 1,
	}
	switch b[3] {
	case 0:
		// RS disabled
	case 1:
		// Legacy sentinel: both old volumes (which stored a boolean) and new volumes
		// encrypted with default parity write flags[3]=1. Custom parity (>=2) is always
		// stored as the actual byte count, so 1 is unambiguously "RS on, default parity".
		f.RSParityBytes = encoding.DefaultRS128ParityBytes
		f.ReedSolomon = true
	default:
		f.RSParityBytes = int(b[3])
		f.ReedSolomon = true
	}
	return f
}

// VolumeHeader contains all header fields for a Picocrypt volume
type VolumeHeader struct {
	// Metadata
	Version  string // "v2.08" or "v1.xx"
	Comments string // User-provided comments (plaintext, not encrypted!)
	Flags    Flags

	// Cryptographic parameters
	Salt      []byte // 16 bytes - Argon2 salt
	HKDFSalt  []byte // 32 bytes - HKDF-SHA3 salt
	SerpentIV []byte // 16 bytes - Serpent IV
	Nonce     []byte // 24 bytes - XChaCha20 nonce

	// Authentication
	KeyHash     []byte // 64 bytes - v2: HMAC-SHA3-512 of header; v1: SHA3-512(key)
	KeyfileHash []byte // 32 bytes - SHA3-256 of keyfile key (or zeros if no keyfiles)
	AuthTag     []byte // 64 bytes - MAC of ciphertext (BLAKE2b or HMAC-SHA3)
}

// NewVolumeHeader creates a new header with default values and provided crypto params
func NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce []byte) *VolumeHeader {
	return &VolumeHeader{
		Version:     CurrentVersion,
		Salt:        salt,
		HKDFSalt:    hkdfSalt,
		SerpentIV:   serpentIV,
		Nonce:       nonce,
		KeyHash:     make([]byte, KeyHashSize),
		KeyfileHash: make([]byte, KeyfileHashSize),
		AuthTag:     make([]byte, AuthTagSize),
	}
}

// IsLegacyV1 returns true if this header is from a v1.x volume
func (h *VolumeHeader) IsLegacyV1() bool {
	return len(h.Version) >= 2 && h.Version[:2] == "v1"
}

// Codecs returns the Reed-Solomon codecs needed for header encoding/decoding
type Codecs struct {
	*encoding.RSCodecs
}

// NewCodecs creates a new Codecs instance wrapping the encoding.RSCodecs
func NewCodecs(rs *encoding.RSCodecs) *Codecs {
	return &Codecs{RSCodecs: rs}
}
