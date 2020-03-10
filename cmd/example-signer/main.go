package main

import (
	"flag"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/m-lab/access/token"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/pretty"
	"github.com/m-lab/go/rtx"
)

var (
	privKey flagx.FileBytes
	subject string
	machine string
)

func init() {
	flag.Var(&privKey, "private", "Private JWT format key used for signing")
	flag.StringVar(&subject, "subject", "", "Subject to use in the jwt Claim")
	flag.StringVar(&machine, "machine", "", "Short machine name used as Audience in the jwt Claim")
}

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Failed to read args from env")

	// Normally, a single process would be either a signer or a verifier. For
	// this example, we create both.
	priv, err := token.NewSigner(privKey)
	rtx.Must(err, "Failed to allocate signer")

	// Create a claim, similar to the locate service, and sign it.
	cl := jwt.Claims{
		Issuer:   "locate.measurementlab.net",
		Subject:  subject,
		Audience: jwt.Audience{machine},
		Expiry:   jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
	}
	pretty.Print(cl)

	// Signing the claim generates the compact, JWT string. Normally, this would
	// be added as the access_token= parameter.
	token, err := priv.Sign(cl)
	rtx.Must(err, "Failed to sign claims")
	fmt.Printf("http://localhost:8800/v1/allow?access_token=%s\n", token)
}
