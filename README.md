# GoogleIdTokenVerifier
Use this API to validate a Google ID Token in [Go](https://golang.org/).

Usage:

```
authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"

certs, err := GetCertsFromURL()
// ...  error handling

aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"

fmt.Println(VerifyGoogleIDToken(authToken, certs, aud))
```

Fetching the certificates for Google servers takes some time. You can cache them in a local file for several days:

```
bytes, err := GetCertsBytesFromURL()
// ...  error handling

err = ioutil.WriteFile(cacheFileName, bytes, 0644)
// ...  error handling
```

Then use the cache:

```
bytes, err := ioutil.ReadFile(cache)
if os.IsNotExist(err) {
    err = downloadAndCacheGoogleCerts()
}
// ...  error handling

certs, err = ParseCerts(bytes)
// ...  error handling
```

