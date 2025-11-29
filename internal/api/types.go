package api

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/beardedprincess/you-jwt-this/internal/crypto"
)

type NonceResponse struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type AttestResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type Jwt struct {
	Header  Header
	Payload Payload
}

type Payload struct {
	Nonce    NonceResponse `json:"nonce"`
	Subject  string        `json:"sub"`
	Audience string        `json:"aud"`
	Issued   time.Time     `json:"iss"`
	Jwk      crypto.PubJWK `json:"jwk"`
}

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

// Encodes a JWT object into a string, with each part Base64 URLEncoded and concatenated together with a . (i.e. "Base64Header"."Base64Payload")
func (j *Jwt) Encode() string {
	bHeader, err := json.Marshal(j.Header)
	if err != nil {
		log.Fatal(err)
	}
	encHeader := base64.RawURLEncoding.EncodeToString(bHeader)

	bPayload, err := json.Marshal(j.Payload)
	if err != nil {
		log.Fatal(err)
	}
	encPayload := base64.RawURLEncoding.EncodeToString(bPayload)

	return encHeader + "." + encPayload
}

// Decodes a base64 decoded string into a JWT object
func (j *Jwt) Decode(s string) {
	// The supplied string should be two separate Base64 URLEncoded strings, delimited by a .
	parts := strings.SplitN(s, ".", 2)

	// Decode & unmarshal the hwt header
	bHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(bHeader, &j.Header)
	if err != nil {
		log.Fatal(err)
	}

	// Decode & unmarshal the jwt payload
	bPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(bPayload, &j.Payload)
	if err != nil {
		log.Fatal(err)
	}
}
