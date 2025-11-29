package api

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"
)

type NonceResponse struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

type Jwt struct {
	Header  Header
	Payload Payload
}

type Payload struct {
	NonceID   string    `json:"nonceId"`
	Nonce     string    `json:"nonce"`
	Subject   string    `json:"sub"`
	Audience  string    `json:"aud"`
	Issued    time.Time `'json:"iss"`
	PublicKey string    `'json:"jwk"`
}

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

func (j *Jwt) Encode() string {
	bHeader, err := json.Marshal(j.Header)
	if err != nil {
		log.Fatal(err)
	}
	encHeader := base64.URLEncoding.EncodeToString(bHeader)

	bPayload, err := json.Marshal(j.Payload)
	if err != nil {
		log.Fatal(err)
	}
	encPayload := base64.URLEncoding.EncodeToString(bPayload)

	return encHeader + "." + encPayload
}

// Decodes a base64 decoded string into a JWT object
func (j *Jwt) Decode(s string) {
	// The supplied string should be two separate Base64 URLEncoded strings, delimited by a .
	parts := strings.SplitN(s, ".", 2)

	// Decode & unmarshal the hwt header
	bHeader, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(bHeader, &j.Header)
	if err != nil {
		log.Fatal(err)
	}

	// Decode & unmarshal the jwt payload
	bPayload, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(bPayload, &j.Payload)
	if err != nil {
		log.Fatal(err)
	}
}
