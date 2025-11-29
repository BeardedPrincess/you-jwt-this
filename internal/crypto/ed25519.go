// Crypto wrapper that allows later expansion of different crypto algorithms,
// or the use of better crypto service providers (i.e. HSM, smart-card, TPM, etc.)
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

// Represent the public key as a JWK object
type PubJWK struct {
	Kty string `json:"kty"` // Key Type
	Crv string `json:"crv"` // Curve
	X   string `json:"x"`   // Public key (base64url encoded)
}

// Returns a JWK object for the public key
func GetJWK(pub ed25519.PublicKey) PubJWK {
	return PubJWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// Generates a new keypair
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign signs the message with privateKey and returns a signature.
func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(priv, data)
}

// Verify reports whether sig is a valid signature of message by publicKey.
func Verify(pubJwk PubJWK, data []byte, sig []byte) (bool, error) {
	pub, err := base64.RawURLEncoding.DecodeString(pubJwk.X)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pub, data, sig), nil
}
