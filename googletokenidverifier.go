package GoogleIdTokenVerifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const GoogleCertURL = "https://www.googleapis.com/oauth2/v3/certs"

// Certs is
type Certs struct {
	Keys []keys `json:"keys"`
}

type keys struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
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

// VerifyGoogleIDToken is
func VerifyGoogleIDToken(authToken string, certs *Certs, audience string) (*TokenInfo, error) {
	header, payload, signature, messageToSign := divideAuthToken(authToken)
	fmt.Printf("authToken\n  header %s\n  payload %s\n  signature %v\n  messageToSign %v\n", string(header), string(payload), signature, messageToSign)

	token, err := getTokenInfo(payload)
	if err != nil {
		return nil, err
	}

	fmt.Printf("token %#v\n", token)
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

	pKey := rsa.PublicKey{N: a5(urlsafeB64decode(key.N)), E: a4(a2(urlsafeB64decode(key.E)))}
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

//GetCertsFromURL is obtained Google's public keys.
func GetCertsFromURL() (*Certs, error) {
	bytes, err := GetCertsBytesFromURL()
	if err != nil {
		return nil, err
	}
	return ParseCerts(bytes)
}

func GetCertsBytesFromURL() ([]byte, error) {
	res, err := http.Get(GoogleCertURL)
	if err != nil {
		return nil, err
	}
	certs, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	return certs, err
}

func ParseCerts(bytes []byte) (*Certs, error) {
	var certs Certs
	err := json.Unmarshal(bytes, &certs)
	return &certs, err
}

func urlsafeB64decode(str string) []byte {
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	bt, _ := base64.URLEncoding.DecodeString(str)
	return bt
}

func choiceKeyByKeyID(kk []keys, tokenKid string) (keys, error) {
	for _, k := range kk {
		if k.Kid == tokenKid {
			return k, nil
		}
	}
	return keys{}, errors.New("Invalid token: mismatched cert key id.")
}

func getAuthTokenKeyID(bt []byte) (string, error) {
	var keys keys
	err := json.Unmarshal(bt, &keys)
	if err != nil {
		return "", err
	}
	return keys.Kid, nil
}

func divideAuthToken(str string) ([]byte, []byte, []byte, []byte) {
	args := strings.Split(str, ".")
	return urlsafeB64decode(args[0]), urlsafeB64decode(args[1]), urlsafeB64decode(args[2]), a3(args[0] + "." + args[1])
}

func a2(bt []byte) *bytes.Reader {
	var bt2 []byte
	if len(bt) < 8 {
		bt2 = make([]byte, 8-len(bt), 8)
		bt2 = append(bt2, bt...)
	} else {
		bt2 = bt
	}
	return bytes.NewReader(bt2)
}

func a3(str string) []byte {
	a := sha256.New()
	a.Write([]byte(str))
	return a.Sum(nil)
}

func a4(a io.Reader) int {
	var e uint64
	binary.Read(a, binary.BigEndian, &e)
	return int(e)
}

func a5(bt []byte) *big.Int {
	a := big.NewInt(0)
	a.SetBytes(bt)
	return a
}

