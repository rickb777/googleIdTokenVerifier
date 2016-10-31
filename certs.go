package googleIdTokenVerifier

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"
)

const GoogleCertURL = "https://www.googleapis.com/oauth2/v3/certs"

const CacheFile = "google-oauth2-v3.jwk"

var certCache *Certs
var nextCacheRefresh time.Time
var mutex = &sync.Mutex{}

func cacheFileName() string {
	return os.TempDir() + "/" + CacheFile
}

func getCachedCertsFromFile(name string) *Certs {
	b, err := ioutil.ReadFile(name)
	if err == nil {
		c, err := ParseCerts(b)
		if err == nil {
			return c
		}
	}
	return nil
}

// GetCertsFromURL fetches Google's public keys and caches them in memory for the duration specified.
func GetCachedCertsFromURL(cacheLifetime time.Duration) (*Certs, error) {
	var err error
	now := time.Now()

	mutex.Lock()
	defer mutex.Unlock()

	needRefresh := now.After(nextCacheRefresh)

	if certCache == nil && !needRefresh {
		certCache = getCachedCertsFromFile(cacheFileName())
	}

	if certCache == nil || needRefresh {
		var b []byte
		certCache, b, err = doGetCertsFromURL()
		if err != nil {
			return nil, err
		}
		ioutil.WriteFile(cacheFileName(), b, 0644) // error is ignored
		nextCacheRefresh = now.Add(cacheLifetime)
	}

	return certCache, nil
}

// GetCertsFromURL fetches Google's public keys.
func doGetCertsFromURL() (*Certs, []byte, error) {
	b, err := GetCertsBytesFromURL()
	if err != nil {
		return nil, nil, err
	}
	c, err := ParseCerts(b)
	return c, b, err
}

// GetCertsFromURL fetches Google's public keys.
func GetCertsFromURL() (*Certs, error) {
	c, _, err := doGetCertsFromURL()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func GetCertsBytesFromURL() ([]byte, error) {
	res, err := http.Get(GoogleCertURL)
	defer res.Body.Close()
	if err != nil {
		return nil, err
	}
	certs, err := ioutil.ReadAll(res.Body)
	return certs, err
}

func ParseCerts(bytes []byte) (*Certs, error) {
	var certs Certs
	err := json.Unmarshal(bytes, &certs)
	return &certs, err
}
