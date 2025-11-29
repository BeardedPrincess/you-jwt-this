// Crypto wrapper that allows later expansion of different crypto algorithms,
// or the use of better crypto service providers (i.e. HSM, smart-card, TPM, etc.)
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// Represent the public key as a JWK object
type JWK struct {
	Kty string `json:"kty"`         // Key Type
	Crv string `json:"crv"`         // Curve
	X   string `json:"x"`           // Public key (base64url encoded)
	D   string `json:"d,omitempty"` // Private key (base64url encoded, omit if public only)
}

// Returns a JWK object for the public key
func GetJWK(pub ed25519.PublicKey, priv ...ed25519.PrivateKey) JWK {
	retJwk := JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}

	if len(priv) > 0 {
		retJwk.D = base64.RawURLEncoding.EncodeToString(priv[0])
	}

	return retJwk
}

// Generates a new keypair
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Loads an existing ed25519 key from a JWK json file
func LoadFromFile(p string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	var pub ed25519.PublicKey = nil
	var priv ed25519.PrivateKey = nil

	// The file doesn't exist, we can't read from there!
	if _, err := os.Stat(p); err != nil {
		return nil, nil, err
	}

	// Attempt to open and read the file
	file, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var jwk JWK
	if err := json.NewDecoder(file).Decode(&jwk); err != nil {
		return nil, nil, err
	}

	// Extract the public key
	pub, err = base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, nil, err
	}

	// Make sure the key is at least the right length of bytes
	if len(pub) != 32 && len(pub) != 64 {
		return nil, nil, fmt.Errorf("invalid public key in file '%s'", p)
	}

	// Extract the private key
	priv, err = base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, nil, err
	}

	// Make sure the key is at least the right length of bytes
	if len(pub) != 32 {
		return nil, nil, fmt.Errorf("invalid private key in file '%s'", p)
	}

	return pub, priv, err
}

// Loads an existing ed25519 key from a JWK json file
func SaveToFile(filePath string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	// Attempt to create the file
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var jwk JWK = GetJWK(pub, priv)
	if err := json.NewEncoder(file).Encode(jwk); err != nil {
		return err
	}

	return nil
}

// Sign signs the message with privateKey and returns a signature.
func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(priv, data)
}

// Verify reports whether sig is a valid signature of message by publicKey.
func Verify(pubJwk JWK, data []byte, sig []byte) (bool, error) {
	pub, err := base64.RawURLEncoding.DecodeString(pubJwk.X)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pub, data, sig), nil
}
