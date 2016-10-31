package googleIdTokenVerifier

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGetCachedCertsFromURL(t *testing.T) {
	os.Remove(cacheFileName())
	os.Remove(CacheFile)

	testGetCertsFromURLWithoutCache(t)
	TestGetCertsFromURL(t)

	c, err := GetCachedCertsFromURL(time.Hour)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	if c == nil {
		t.Fatalf("no cert\n")
	}

	c, err = GetCachedCertsFromURL(time.Hour)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	if c == nil {
		t.Fatalf("no cert\n")
	}

	c, err = GetCachedCertsFromURL(time.Hour)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	if c == nil {
		t.Fatalf("no cert\n")
	}
}

func TestGetCertsFromURL(t *testing.T) {
	cb, err := ioutil.ReadFile(CacheFile)
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
		if len(bytes) == len(cb) {
			for i, _ := range bytes {
				if bytes[i] != cb[i] {
					t.Fatalf("index %d got %d, want %d\n", i, bytes[i], cb[i])
				}
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

	err = ioutil.WriteFile(CacheFile, bytes, 0644)
	if err != nil {
		t.Fatalf("got %v", err)
	}
}

func TestGetCachedKeyByKeyID_whenNotMatched(t *testing.T) {
	_, err := ioutil.ReadFile(CacheFile)
	if os.IsNotExist(err) {
		testGetCertsFromURLWithoutCache(t)
	} else if err != nil {
		t.Fatalf("%v\n", err)
	}
	_, err = GetCachedKeyByKeyID("XX", "YY", time.Hour)
	if err == nil {
		t.Errorf("expected error")
	} else {
		m := err.Error()
		if !strings.HasPrefix(m, "Invalid token:") {
			t.Errorf(m)
		}
	}
}

func TestGetCachedKeyByKeyID_whenMatched(t *testing.T) {
	_, err := ioutil.ReadFile(CacheFile)
	if os.IsNotExist(err) {
		testGetCertsFromURLWithoutCache(t)
	} else if err != nil {
		t.Fatalf("%v\n", err)
	}

	k0 := certCache.Keys[0]
	key, err := GetCachedKeyByKeyID(k0.Alg, k0.Kid, time.Hour)
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if key == nil {
		t.Fatalf("got nil key")
	}

	// repeat
	key, err = GetCachedKeyByKeyID(k0.Alg, k0.Kid, time.Hour)
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if key == nil {
		t.Fatalf("got nil key")
	}
}

func TestParseCerts(t *testing.T) {
	bytes, err := ioutil.ReadFile(CacheFile)
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
	bytes, err := ioutil.ReadFile(CacheFile)
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
