// Command mint-jwt is a small dev/demo utility that mints an HS256 JWT
// signed with the same shared secret the proxy is configured with, for
// exercising the JWT-fallback auth path without standing up a real IdP.
// NOT for production issuance.
package main

import (
	"flag"
	"fmt"
	"time"

	"zero-trust-iap/internal/identity"
)

func main() {
	secret := flag.String("secret", "", "HMAC secret (must match proxy's jwt_hmac_secret / IAP_JWT_SECRET)")
	subject := flag.String("sub", "demo-user", "JWT subject")
	issuer := flag.String("iss", "iap-dev-issuer", "JWT issuer")
	audience := flag.String("aud", "iap-admin-ui", "JWT audience")
	ttl := flag.Duration("ttl", 10*time.Minute, "token lifetime")
	flag.Parse()

	if *secret == "" {
		fmt.Println("error: -secret is required")
		return
	}

	tok, err := identity.SignHS256([]byte(*secret), identity.Claims{
		Subject:   *subject,
		Issuer:    *issuer,
		Audience:  *audience,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(*ttl).Unix(),
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(tok)
}
