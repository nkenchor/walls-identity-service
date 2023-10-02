package helper

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2HashManager struct {
	timeCost   uint32
	memoryCost uint32
	threads    uint8
	hashLength uint32
	saltLength uint32
}

func NewArgon2HashManager() *Argon2HashManager {
	return &Argon2HashManager{
		timeCost:   3,
		memoryCost: 64 * 1024,
		threads:    4,
		hashLength: 32,
		saltLength: 16,
	}
}

func (m *Argon2HashManager) CreateHash(password string) (string, error) {
	salt, err := generateRandomBytes(m.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, m.timeCost, m.memoryCost, m.threads, m.hashLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	fullHash := fmt.Sprintf(format, argon2.Version, m.memoryCost, m.timeCost, m.threads, b64Salt, b64Hash)

	return fullHash, nil
}

func (m *Argon2HashManager) CompareHash(password, encodedHash string) (bool, error) {

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}
	
	v, err := strconv.Atoi(parts[2][2:]) // taking "v=%d" in the format and removing "v="
	if err != nil {
		return false, errors.New("invalid hash format")
	}
	if v != argon2.Version {
		return false, fmt.Errorf("incompatible argon2 version: expected %d, got %d", argon2.Version, v)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		fmt.Println("error decoding salt:", err)
		return false, err
	}

	actualHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		fmt.Println("error decoding hash:", err)
		return false, err
	}

	expectedHash := argon2.IDKey([]byte(password), salt, m.timeCost, m.memoryCost, m.threads, m.hashLength)

	return string(actualHash) == string(expectedHash), nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
