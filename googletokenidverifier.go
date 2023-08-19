package googleIdTokenVerifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"time"
)

type Key struct {
	Kty string           `json:"kty"`
	Alg string           `json:"alg"`
	Use string           `json:"use"`
	Kid string           `json:"kid"`
	N   string           `json:"n"`
	E   string           `json:"e"`
	Key crypto.PublicKey `json:"-"`
}

type Certs struct {
	Keys []Key `json:"keys"`
}

// TokenInfo is
type TokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	AtHash        string `json:"at_hash"`
	Aud           string `json:"aud"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

// https://developers.google.com/identity/sign-in/web/backend-auth
// https://github.com/google/oauth2client/blob/master/oauth2client/crypt.py

// VerifyGoogleIDToken verifies the authentication token received by the Google client (typically Javascript code).
func VerifyGoogleIDToken(authToken string, certs *Certs, audience string) (*TokenInfo, error) {
	header, payload, signature, messageToSign := divideAuthToken(authToken)
	logf("authToken", "header", string(header), "payload", string(payload), "signature", signature, "messageToSign", messageToSign)

	token, err := getTokenInfo(payload)
	if err != nil {
		return nil, err
	}

	logf("tokenInfo", "token", token)
	if audience != token.Aud {
		return nil, errors.New("Invalid token: incorrect audience.")
	}

	if (token.Iss != "accounts.google.com") && (token.Iss != "https://accounts.google.com") {
		return nil, errors.New("Invalid token: incorrect issuer.")
	}

	if !checkTime(token) {
		return nil, errors.New("Invalid token: it has expired.")
	}

	tokenKid, err := getAuthTokenKeyID(header)
	if err != nil {
		return nil, err
	}

	key, err := choiceKeyByKeyID(certs.Keys, tokenKid)
	if err != nil {
		return nil, err
	}

	pKey := rsa.PublicKey{N: byteToInt(urlsafeB64decode(key.N)), E: btrToInt(byteToBtr(urlsafeB64decode(key.E)))}
	err = rsa.VerifyPKCS1v15(&pKey, crypto.SHA256, messageToSign, signature)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func getTokenInfo(bytes []byte) (*TokenInfo, error) {
	var ti *TokenInfo
	err := json.Unmarshal(bytes, &ti)
	return ti, err
}

func checkTime(tokeninfo *TokenInfo) bool {
	if (time.Now().Unix() < tokeninfo.Iat) || (time.Now().Unix() > tokeninfo.Exp) {
		return false
	}
	return true
}

func urlsafeB64decode(str string) []byte {
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	bt, _ := base64.URLEncoding.DecodeString(str)
	return bt
}

func choiceKeyByKeyID(kk []Key, tokenKid string) (Key, error) {
	for _, k := range kk {
		if k.Kid == tokenKid {
			return k, nil
		}
	}
	return Key{}, errors.New("Invalid token: mismatched cert key id.")
}

func getAuthTokenKeyID(bt []byte) (string, error) {
	var keys Key
	err := json.Unmarshal(bt, &keys)
	if err != nil {
		return "", err
	}
	return keys.Kid, nil
}

func divideAuthToken(str string) ([]byte, []byte, []byte, []byte) {
	args := strings.Split(str, ".")
	return urlsafeB64decode(args[0]), urlsafeB64decode(args[1]), urlsafeB64decode(args[2]), calcSum(args[0] + "." + args[1])
}

func byteToBtr(bt0 []byte) *bytes.Reader {
	var bt1 []byte
	if len(bt0) < 8 {
		bt1 = make([]byte, 8-len(bt0), 8)
		bt1 = append(bt1, bt0...)
	} else {
		bt1 = bt0
	}
	return bytes.NewReader(bt1)
}

func calcSum(str string) []byte {
	a := sha256.New()
	a.Write([]byte(str))
	return a.Sum(nil)
}

func btrToInt(a io.Reader) int {
	var e uint64
	binary.Read(a, binary.BigEndian, &e)
	return int(e)
}

func byteToInt(bt []byte) *big.Int {
	a := big.NewInt(0)
	a.SetBytes(bt)
	return a
}
