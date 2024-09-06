//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cryptoutils

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" // nolint:gosec
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	x5092 "github.com/tjfoc/gmsm/x509"

	"github.com/letsencrypt/boulder/goodkey"
)

const (
	// PublicKeyPEMType is the string "PUBLIC KEY" to be used during PEM encoding and decoding
	PublicKeyPEMType PEMType = "PUBLIC KEY"
	// PKCS1PublicKeyPEMType is the string "RSA PUBLIC KEY" used to parse PKCS#1-encoded public keys
	PKCS1PublicKeyPEMType PEMType = "RSA PUBLIC KEY"
)

// subjectPublicKeyInfo is used to construct a subject key ID.
// https://tools.ietf.org/html/rfc5280#section-4.1.2.7
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// UnmarshalPEMToPublicKey converts a PEM-encoded byte slice into a crypto.PublicKey
func UnmarshalPEMToPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	derBytes, _ := pem.Decode(pemBytes)
	if derBytes == nil {
		return nil, errors.New("PEM decoding failed")
	}
	switch derBytes.Type {
	case string(PublicKeyPEMType):
		pub, err := x509.ParsePKIXPublicKey(derBytes.Bytes)
		if err != nil {
			fmt.Println("gm sm2 ParsePKIXPublicKey")
			pub, err = x5092.ParsePKIXPublicKey(derBytes.Bytes)
			pubKey, ok := pub.(*ecdsa.PublicKey)
			if ok {
				if pubKey.Curve == sm2.P256Sm2() {
					pub = sm2.PublicKey{
						Curve: pubKey.Curve,
						X:     pubKey.X,
						Y:     pubKey.Y,
					}
				}
			}
		}
		fmt.Println(fmt.Sprintf("ParsePKIXPublicKey pub: %T, err： %v", pub, err))
		return pub, err
	case string(PKCS1PublicKeyPEMType):
		return x509.ParsePKCS1PublicKey(derBytes.Bytes)
	default:
		return nil, fmt.Errorf("unknown Public key PEM file type: %v. Are you passing the correct public key?",
			derBytes.Type)
	}
}

// MarshalPublicKeyToDER converts a crypto.PublicKey into a PKIX, ASN.1 DER byte slice
func MarshalPublicKeyToDER(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("empty key")
	}
	k, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fmt.Println(fmt.Sprintf("MarshalPublicKeyToDER try sm2"))
		value, ok := pub.(sm2.PublicKey)
		if !ok {
			fmt.Println(fmt.Sprintf("assert pub sm2.PublicKey failed"))
		}
		p := &value
		fmt.Println(fmt.Sprintf("MarshalPublicKeyToDER t: %T", p))
		k, err = x5092.MarshalPKIXPublicKey(p)
	}
	return k, err
}

// MarshalPublicKeyToPEM converts a crypto.PublicKey into a PEM-encoded byte slice
func MarshalPublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	derBytes, err := MarshalPublicKeyToDER(pub)
	if err != nil {
		return nil, err
	}
	return PEMEncode(PublicKeyPEMType, derBytes), nil
}

// SKID generates a 160-bit SHA-1 hash of the value of the BIT STRING
// subjectPublicKey (excluding the tag, length, and number of unused bits).
// https://tools.ietf.org/html/rfc5280#section-4.2.1.2
func SKID(pub crypto.PublicKey) ([]byte, error) {
	derPubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(derPubBytes, &spki); err != nil {
		return nil, err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes) // nolint:gosec
	return skid[:], nil
}

// EqualKeys compares two public keys. Supports RSA, ECDSA and ED25519.
// If not equal, the error message contains hex-encoded SHA1 hashes of the DER-encoded keys
func EqualKeys(first, second crypto.PublicKey) error {
	switch pub := first.(type) {
	case *rsa.PublicKey:
		if !pub.Equal(second) {
			return fmt.Errorf(genErrMsg(first, second, "rsa"))
		}
	case *ecdsa.PublicKey:
		if !pub.Equal(second) {
			return fmt.Errorf(genErrMsg(first, second, "ecdsa"))
		}
	case ed25519.PublicKey:
		if !pub.Equal(second) {
			return fmt.Errorf(genErrMsg(first, second, "ed25519"))
		}
	default:
		return errors.New("unsupported key type")
	}
	return nil
}

// genErrMsg generates an error message for EqualKeys
func genErrMsg(first, second crypto.PublicKey, keyType string) string {
	msg := fmt.Sprintf("%s public keys are not equal", keyType)
	// Calculate SKID to include in error message
	firstSKID, err := SKID(first)
	if err != nil {
		return msg
	}
	secondSKID, err := SKID(second)
	if err != nil {
		return msg
	}
	return fmt.Sprintf("%s (%s, %s)", msg, hex.EncodeToString(firstSKID), hex.EncodeToString(secondSKID))
}

// ValidatePubKey validates the parameters of an RSA, ECDSA, or ED25519 public key.
func ValidatePubKey(pub crypto.PublicKey) error {
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		// goodkey policy enforces:
		// * Size of key: 2048 <= size <= 4096, size % 8 = 0
		// * Exponent E = 65537 (Default exponent for OpenSSL and Golang)
		// * Small primes check for modulus
		// * Weak keys generated by Infineon hardware (see https://crocs.fi.muni.cz/public/papers/rsa_ccs17)
		// * Key is easily factored with Fermat's factorization method
		p, err := goodkey.NewKeyPolicy(&goodkey.Config{FermatRounds: 100}, nil)
		if err != nil {
			// Should not occur, only chances to return errors are if fermat rounds
			// are <0 or when loading blocked/weak keys from disk (not used here)
			return errors.New("unable to initialize key policy")
		}
		// ctx is unused
		return p.GoodKey(context.Background(), pub)
	case *ecdsa.PublicKey:
		// Unable to use goodkey policy because P-521 curve is not supported
		return validateEcdsaKey(pk)
	case ed25519.PublicKey:
		return validateEd25519Key(pk)
	}
	return errors.New("unsupported public key type")
}

// Enforce that the ECDSA key curve is one of:
// * NIST P-256 (secp256r1, prime256v1)
// * NIST P-384
// * NIST P-521.
// Other EC curves, like secp256k1, are not supported by Go.
func validateEcdsaKey(pub *ecdsa.PublicKey) error {
	switch pub.Curve {
	case elliptic.P224():
		return fmt.Errorf("unsupported ec curve, expected NIST P-256, P-384, or P-521")
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return nil
	default:
		return fmt.Errorf("unexpected ec curve")
	}
}

// No validations currently, ED25519 supports only one key size.
func validateEd25519Key(_ ed25519.PublicKey) error {
	return nil
}
