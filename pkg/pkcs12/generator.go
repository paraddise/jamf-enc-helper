package pkcs12

import (
	"encoding/binary"
	"hash"
	"unicode/utf16"
)

// https://www.foo.be/docs-free/opensst/ref/pkcs-12v1.pdf
// See org.bouncycastle.crypto.PBEParametersGenerator for reference

const (
	KeyMaterial = 1
	IVMaterial  = 2
	MACMaterial = 3
)

// PKCS12ParametersGenerator implements PKCS#12 key derivation as per BouncyCastle
type PKCS12ParametersGenerator struct {
	digest         hash.Hash
	u              int // digest size
	v              int // block size (byte length)
	password       []byte
	salt           []byte
	iterationCount int
}

// NewPKCS12ParametersGenerator creates a new PKCS12 parameters generator
// The digest must have a known block size (e.g., SHA-256 has block size 64)
func NewPKCS12ParametersGenerator(digest hash.Hash) *PKCS12ParametersGenerator {
	u := digest.Size()

	// Determine block size based on digest type
	// For standard hashes: SHA-1 (64), SHA-256 (64), SHA-512 (128), etc.
	var v int
	switch u {
	case 20: // SHA-1
		v = 64
	case 32: // SHA-256, SHA-224
		v = 64
	case 48: // SHA-384
		v = 128
	case 64: // SHA-512
		v = 128
	default:
		// Default assumption: most common case is SHA-256
		v = 64
	}

	return &PKCS12ParametersGenerator{
		digest: digest,
		u:      u,
		v:      v,
	}
}

// Init initializes the generator with password, salt, and iteration count
func (g *PKCS12ParametersGenerator) Init(password, salt []byte, iterationCount int) {
	g.password = password
	g.salt = salt
	g.iterationCount = iterationCount
}

// adjust modifies the concatenated buffer by adding the previous output
func (g *PKCS12ParametersGenerator) adjust(data []byte, offset int, prev []byte) {
	carry := int(data[offset+len(prev)-1]) + int(prev[len(prev)-1]) + 1
	data[offset+len(prev)-1] = byte(carry)
	carry >>= 8

	for i := len(prev) - 2; i >= 0; i-- {
		carry += int(prev[i]) + int(data[offset+i])
		data[offset+i] = byte(carry)
		carry >>= 8
	}
}

// generateDerivedKey generates a derived key of the specified type and length
func (g *PKCS12ParametersGenerator) generateDerivedKey(materialType int, keyLen int) []byte {
	// Initialize D
	d := make([]byte, g.v)
	for i := range d {
		d[i] = byte(materialType)
	}

	// Prepare salt buffer
	var saltBuf []byte
	if len(g.salt) > 0 {
		saltBuf = make([]byte, g.v*((len(g.salt)+g.v-1)/g.v))
		for i := range saltBuf {
			saltBuf[i] = g.salt[i%len(g.salt)]
		}
	} else {
		saltBuf = []byte{}
	}

	// Prepare password buffer
	var passwordBuf []byte
	if len(g.password) > 0 {
		passwordBuf = make([]byte, g.v*((len(g.password)+g.v-1)/g.v))
		for i := range passwordBuf {
			passwordBuf[i] = g.password[i%len(g.password)]
		}
	} else {
		passwordBuf = []byte{}
	}

	// Concatenate salt and password
	s := make([]byte, len(saltBuf)+len(passwordBuf))
	copy(s, saltBuf)
	copy(s[len(saltBuf):], passwordBuf)

	// Output buffer
	output := make([]byte, keyLen)

	// Number of iterations needed
	iterations := (keyLen + g.u - 1) / g.u

	// B buffer
	b := make([]byte, g.v)

	for i := 1; i <= iterations; i++ {
		// Reset digest
		g.digest.Reset()

		// Update with D
		g.digest.Write(d)

		// Update with S
		g.digest.Write(s)

		// Get first hash
		// Sum appends to the provided slice, so we use nil to get a new slice
		a := g.digest.Sum(nil)
		if len(a) != g.u {
			// Ensure a is exactly g.u bytes
			tmp := make([]byte, g.u)
			copy(tmp, a)
			a = tmp
		}

		// Iterate hash more times
		for j := 1; j < g.iterationCount; j++ {
			g.digest.Reset()
			g.digest.Write(a)
			hashResult := g.digest.Sum(nil)
			if len(hashResult) != g.u {
				tmp := make([]byte, g.u)
				copy(tmp, hashResult)
				a = tmp
			} else {
				a = hashResult
			}
		}

		// Fill B buffer by repeating a to fill v bytes
		for j := range b {
			b[j] = a[j%len(a)]
		}

		// Adjust S in blocks of v bytes
		for j := 0; j < len(s)/g.v; j++ {
			g.adjust(s, j*g.v, b)
		}

		// Copy to output
		startIdx := (i - 1) * g.u
		if i == iterations {
			// Last iteration: only copy what's needed
			remainingLen := min(len(output)-startIdx, len(a))
			copy(output[startIdx:], a[:remainingLen])
		} else {
			copy(output[startIdx:], a)
		}
	}

	return output
}

// GenerateDerivedParameters generates both key and IV
// keySize and ivSize are in bytes
func (g *PKCS12ParametersGenerator) GenerateDerivedParameters(keySize, ivSize int) ([]byte, []byte) {
	key := g.generateDerivedKey(KeyMaterial, keySize)
	iv := g.generateDerivedKey(IVMaterial, ivSize)
	return key, iv
}

// GenerateDerivedKeyParameters generates only a key
// keySize is in bytes
func (g *PKCS12ParametersGenerator) GenerateDerivedKeyParameters(keySize int) []byte {
	return g.generateDerivedKey(KeyMaterial, keySize)
}

// GenerateDerivedMacParameters generates MAC parameters
// macSize is in bytes
func (g *PKCS12ParametersGenerator) GenerateDerivedMacParameters(macSize int) []byte {
	return g.generateDerivedKey(MACMaterial, macSize)
}

// StringToUnicodeBytes converts a string to UTF-16BE bytes with null terminator (00 00).
// Each character is represented as 2 bytes in big-endian order.
// This matches the Java stringToUnicodeBytes function used in PKCS#12 password encoding.
func StringToUnicodeBytes(str string) []byte {
	// Convert string to UTF-16 code points
	runes := []rune(str)
	utf16CodePoints := utf16.Encode(runes)

	// Allocate buffer: (len(str) + 1) * 2 bytes (each char is 2 bytes + null terminator)
	buf := make([]byte, (len(utf16CodePoints)+1)*2)

	// Write each UTF-16 code point as big-endian uint16 (2 bytes)
	for i, codePoint := range utf16CodePoints {
		binary.BigEndian.PutUint16(buf[i*2:], codePoint)
	}

	// Add null terminator (00 00) at the end
	binary.BigEndian.PutUint16(buf[len(utf16CodePoints)*2:], 0)

	return buf
}
