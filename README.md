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
