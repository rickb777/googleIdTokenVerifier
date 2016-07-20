package GoogleIdTokenVerifier

import (
	"testing"
	"io/ioutil"
	"os"
)

const cache = "google-ouath2.jwk"

func TestGetCertsFromURL(t *testing.T) {
	cb, err := ioutil.ReadFile(cache)
	if os.IsNotExist(err) {
		testGetCertsFromURLWithoutCache(t)
		TestGetCertsFromURL(t)
	} else if err != nil {
		t.Fatalf("%v\n", err)
	}

	bytes, err := GetCertsBytesFromURL()
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	if len(cb) > 0 {
		if len(bytes) == 0 {
			t.Fatalf("No cert data received\n")
		}
		if len(bytes) != len(cb) {
			t.Fatalf("got %d bytes, want %d\n", len(bytes), len(cb))
		}
		for i, _ := range bytes {
			if bytes[i] != cb[i] {
				t.Fatalf("index %d got %d, want %d\n", i, bytes[i], cb[i])
			}
		}
	}
}

func testGetCertsFromURLWithoutCache(t *testing.T) {
	bytes, err := GetCertsBytesFromURL()
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	if len(bytes) == 0 {
		t.Fatalf("No cert data received\n")
	}

	err = ioutil.WriteFile(cache, bytes, 0644)
	if err != nil {
		t.Fatalf("got %v", err)
	}
}

func TestParseCerts(t *testing.T) {
	bytes, err := ioutil.ReadFile(cache)
	if os.IsNotExist(err) {
		testGetCertsFromURLWithoutCache(t)
		TestParseCerts(t)
	} else if err != nil {
		t.Fatalf("%v\n", err)
	}
	_, err = ParseCerts(bytes)
	if err != nil {
		t.Errorf("got %v", err)
	}
}

// This test only works when real credentials are pasted in
func xTestVerify(t *testing.T) {
	bytes, err := ioutil.ReadFile(cache)
	if os.IsNotExist(err) {
		testGetCertsFromURLWithoutCache(t)
		TestParseCerts(t)
	} else if err != nil {
		t.Fatalf("%v\n", err)
	}
	certs, err := ParseCerts(bytes)
	if err != nil {
		t.Errorf("got %v", err)
	}

	authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"
	aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"
	actual, err := VerifyGoogleIDToken(authToken, certs, aud)
	if err != nil {
		t.Errorf("got %v", err)
	}

	var token *TokenInfo
	expected := token
	if actual != expected {
		t.Errorf("got %#v\nwant %#v", actual, expected)
	}
}

