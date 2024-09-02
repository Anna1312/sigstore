package sm2

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	sigopts "github.com/sigstore/sigstore/pkg/signature"
	gmsm2 "github.com/tjfoc/gmsm/sm2"
	"io"
)

type GMSM2Signer struct {
	priv gmsm2.PrivateKey
}

// LoadGMSM2Signer calculates signatures using the specified private key.
func LoadGMSM2Signer(priv gmsm2.PrivateKey) (*GMSM2Signer, error) {

	return &GMSM2Signer{
		priv: priv,
	}, nil
}

// SignMessage signs the provided message. Passing the WithDigest option is not
// supported as ED25519 performs a two pass hash over the message during the
// signing process.
//
// All options are ignored.
func (e GMSM2Signer) SignMessage(message io.Reader, _ ...sigopts.SignOption) ([]byte, error) {
	buffer := bytes.Buffer{}
	_, err := buffer.ReadFrom(message)
	if err != nil {
		return nil, err
	}
	msg := buffer.Bytes()
	return e.priv.Sign(rand.Reader, msg, nil)
}

// Public returns the public key that can be used to verify signatures created by
// this signer.
func (e GMSM2Signer) Public() crypto.PublicKey {
	return e.priv.Public()
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (e GMSM2Signer) PublicKey(_ ...sigopts.PublicKeyOption) (crypto.PublicKey, error) {
	return e.Public(), nil
}

// Sign computes the signature for the specified message; the first and third arguments to this
// function are ignored as they are not used by the ED25519 algorithm.
func (e GMSM2Signer) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	if message == nil {
		return nil, errors.New("message must not be nil")
	}
	return e.SignMessage(bytes.NewReader(message))
}

type GMSM2Verifier struct {
	publicKey gmsm2.PublicKey
}

// LoadGMSM2Verifier returns a Verifier that verifies signatures using the specified ED25519 public key.
func LoadGMSM2Verifier(pub gmsm2.PublicKey) (*GMSM2Verifier, error) {

	return &GMSM2Verifier{
		publicKey: pub,
	}, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (e *GMSM2Verifier) PublicKey(_ ...sigopts.PublicKeyOption) (crypto.PublicKey, error) {
	return e.publicKey, nil
}

// VerifySignature verifies the signature for the given message.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// All options are ignored if specified.
func (e *GMSM2Verifier) VerifySignature(signature, message io.Reader, _ ...sigopts.VerifyOption) error {
	if signature == nil {
		return errors.New("nil signature passed to VerifySignature")
	}

	sigBytes, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	buffer := bytes.Buffer{}
	_, err = buffer.ReadFrom(message)
	if err != nil {
		return err
	}
	messageBytes := buffer.Bytes()

	if !e.publicKey.Verify(messageBytes, sigBytes) {
		return errors.New("failed to verify signature")
	}
	return nil
}

// GMSM2SignerVerifier is a signature.SignerVerifier that uses the Ed25519 public-key signature system
type GMSM2SignerVerifier struct {
	*GMSM2Verifier
	*GMSM2Signer
}

// LoadGMSM2SignerVerifier creates a combined signer and verifier. This is
// a convenience object that simply wraps an instance of ED25519Signer and ED25519Verifier.
func LoadGMSM2SignerVerifier(priv gmsm2.PrivateKey) (*GMSM2SignerVerifier, error) {
	signer, err := LoadGMSM2Signer(priv)
	if err != nil {
		return nil, fmt.Errorf("initializing signer: %w", err)
	}
	pub, ok := priv.Public().(gmsm2.PublicKey)
	if !ok {
		return nil, fmt.Errorf("given key is not ed25519.PublicKey")
	}
	verifier, err := LoadGMSM2Verifier(pub)
	if err != nil {
		return nil, fmt.Errorf("initializing verifier: %w", err)
	}

	return &GMSM2SignerVerifier{
		GMSM2Signer:   signer,
		GMSM2Verifier: verifier,
	}, nil
}

// NewDefaultGMSM2SignerVerifier creates a combined signer and verifier using ED25519.
// This creates a new ED25519 key using crypto/rand as an entropy source.
func NewDefaultGMSM2SignerVerifier() (*GMSM2SignerVerifier, gmsm2.PrivateKey, error) {
	return NewGMSM2SignerVerifier(rand.Reader)
}

// NewGMSM2SignerVerifier creates a combined signer and verifier using ED25519.
// This creates a new ED25519 key using the specified entropy source.
func NewGMSM2SignerVerifier(rand io.Reader) (*GMSM2SignerVerifier, gmsm2.PrivateKey, error) {
	priv, err := gmsm2.GenerateKey(rand)

	sv, err := LoadGMSM2SignerVerifier(*priv)
	if err != nil {
		return nil, gmsm2.PrivateKey{}, err
	}

	return sv, *priv, nil
}

// PublicKey returns the public key that is used to verify signatures by
// this verifier. As this value is held in memory, all options provided in arguments
// to this method are ignored.
func (e GMSM2SignerVerifier) PublicKey(_ ...sigopts.PublicKeyOption) (crypto.PublicKey, error) {
	return e.publicKey, nil
}
