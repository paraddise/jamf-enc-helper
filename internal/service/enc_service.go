package service

import (
	"crypto/hmac"
	"crypto/sha256"
)

var DefaultApiSalt = []byte("rn337^!h#!75t+jp@n%3^^6=4)1xe0x)oaap+##zw&4-uf5zj+")
var DefaultSamlTokenSalt = []byte("58^ip+2f_+7xcy^hg*6rqel_cc!6m=#h3(ghd!vg2*e!+#$ih=")

type EncryptionService struct {
	EncryptionKey []byte
}

func New(encryptionKey []byte) *EncryptionService {
	return &EncryptionService{EncryptionKey: encryptionKey}
}

func (s *EncryptionService) GetSecret(salt []byte) []byte {
	// Init hmacsha256 with salt
	// make hmac from encryption key
	hmac := hmac.New(sha256.New, salt)
	hmac.Write(s.EncryptionKey)
	return hmac.Sum(nil)
}
