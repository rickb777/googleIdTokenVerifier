package googleIdTokenVerifier

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"time"
)

func GetCachedKeyByKeyID(alg, kid string, cacheLifetime time.Duration) (crypto.PublicKey, error) {
	certs, err := GetCachedCertsFromURL(cacheLifetime)
	if err != nil {
		return nil, err
	}
	for _, k := range certs.Keys {
		if k.Alg == alg && k.Kid == kid {
			switch k.Kty {
			case "RSA":
				if k.Key == nil {
					k.Key = &rsa.PublicKey{N: a5(urlsafeB64decode(k.N)), E: a4(a2(urlsafeB64decode(k.E)))}
				}
				return k.Key, nil
			}
		}
	}
	return nil, fmt.Errorf("Invalid token: mismatched %s cert key id %s (only RSA keys are currently supported).", alg, kid)
}
