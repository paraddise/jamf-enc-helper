package dbencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"regexp"

	"github.com/paraddise/jamf-enc-helper/internal/logger"
	"github.com/paraddise/jamf-enc-helper/pkg/pkcs12"
)

var databaseKeyFormat = regexp.MustCompile(`^[a-v0-9]*$`)

const DefaultPhrase = "2M#84->)y^%2kGmN97ZLfhbL|-M:j?"

// Default Salt -87,-101,-56,50,86,53,-29,3
var DefaultSalt = []byte{169, 155, 200, 50, 86, 53, 227, 3}

const DefaultIteractionCount = 19

type Config struct {
	Phrase          string
	Salt            []byte
	IteractionCount int
}

type DBEncryptionService struct {
	config *Config
}

func DefaultConfig() *Config {
	return &Config{
		Phrase:          DefaultPhrase,
		Salt:            DefaultSalt,
		IteractionCount: DefaultIteractionCount,
	}
}

func NewDBEncryptionService(config *Config) *DBEncryptionService {
	return &DBEncryptionService{config: config}
}

// PBEWithSHA256And256BitAES-CBC-BC implementation

func (s *DBEncryptionService) DecryptKeyFromDatabase(encryptedKey []byte) ([]byte, error) {
	passphrase := pkcs12.StringToUnicodeBytes(s.config.Phrase)
	logger.Debug("passphrase: %v", passphrase)
	salt := s.config.Salt
	logger.Debug("salt: %v", salt)
	iterations := s.config.IteractionCount
	logger.Debug("iterations: %d", iterations)

	generator := pkcs12.NewPKCS12ParametersGenerator(sha256.New())
	generator.Init(passphrase, salt, iterations)
	key, iv := generator.GenerateDerivedParameters(32, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("Failed to create AES cipher: %v", err)
		return nil, err
	}

	// Check if ciphertext length is a multiple of block size
	if len(encryptedKey)%aes.BlockSize != 0 {
		err := fmt.Errorf("ciphertext length is not a multiple of block size: %d", len(encryptedKey))
		logger.Error("%v", err)
		return nil, err
	}

	// Create CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt
	decryptedKey := make([]byte, len(encryptedKey))
	mode.CryptBlocks(decryptedKey, encryptedKey)

	// Remove PKCS7 padding
	// The last byte indicates the padding length
	if len(decryptedKey) == 0 {
		err := fmt.Errorf("decrypted data is empty")
		logger.Error("%v", err)
		return nil, err
	}

	paddingLen := int(decryptedKey[len(decryptedKey)-1])
	if paddingLen > aes.BlockSize || paddingLen == 0 {
		err := fmt.Errorf("invalid padding length: %d", paddingLen)
		logger.Error("%v", err)
		return nil, err
	}

	if paddingLen > len(decryptedKey) {
		err := fmt.Errorf("padding length %d exceeds data length %d", paddingLen, len(decryptedKey))
		logger.Error("%v", err)
		return nil, err
	}

	// Verify padding
	for i := len(decryptedKey) - paddingLen; i < len(decryptedKey); i++ {
		if decryptedKey[i] != byte(paddingLen) {
			err := fmt.Errorf("invalid padding")
			logger.Error("%v", err)
			return nil, err
		}
	}

	// Remove padding
	decryptedKey = decryptedKey[:len(decryptedKey)-paddingLen]

	if !databaseKeyFormat.MatchString(string(decryptedKey)) {
		err := fmt.Errorf("decrypted key is not in the correct format")
		logger.Error("%v", err)
		return nil, err
	}

	return decryptedKey, nil
}

func (s *DBEncryptionService) EncryptKeyToDatabase(plainKey []byte) ([]byte, error) {
	// Validate key format
	if !databaseKeyFormat.MatchString(string(plainKey)) {
		err := fmt.Errorf("key is not in the correct format")
		logger.Error("%v", err)
		return nil, err
	}

	passphrase := pkcs12.StringToUnicodeBytes(s.config.Phrase)
	salt := s.config.Salt
	iterations := s.config.IteractionCount

	generator := pkcs12.NewPKCS12ParametersGenerator(sha256.New())
	generator.Init(passphrase, salt, iterations)
	key, iv := generator.GenerateDerivedParameters(32, 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("Failed to create AES cipher: %v", err)
		return nil, err
	}

	// Add PKCS7 padding
	paddingLen := aes.BlockSize - (len(plainKey) % aes.BlockSize)
	paddedKey := make([]byte, len(plainKey)+paddingLen)
	copy(paddedKey, plainKey)
	for i := len(plainKey); i < len(paddedKey); i++ {
		paddedKey[i] = byte(paddingLen)
	}

	// Create CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt
	encryptedKey := make([]byte, len(paddedKey))
	mode.CryptBlocks(encryptedKey, paddedKey)

	return encryptedKey, nil
}
