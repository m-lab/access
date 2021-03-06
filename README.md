# Access Control

[![godoc](https://godoc.org/github.com/m-lab/access?status.svg)](https://godoc.org/github.com/m-lab/access)
[![go report card](https://goreportcard.com/badge/github.com/m-lab/access)](https://goreportcard.com/report/github.com/m-lab/access)

Libraries and services for access control on the M-Lab platform.

## Create JSON Web Keys

The `m-lab/access` package support JWK keys generated by `jwk-keygen`.

Create a signing key pair:

```sh
go get gopkg.in/square/go-jose.v2/jwk-keygen
~/bin/jwk-keygen --use=sig --alg=EdDSA --kid=1
```

## Access Envelope Service

For new services, we want to balance access to the platform with protecting
platform integrity and measurement quality.

Until a service supports access control natively, the ["access envelope"
service](cmd/envelope/README.md) accepts access tokens, validates them, and
upon acceptance, adds an iptables rule granting the client IP time to run a
measurement before removing the rule again after a timeout.
