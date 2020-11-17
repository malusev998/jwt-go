package jwt

import (
	"crypto"
	"crypto/hmac"
	"errors"
)

const (
	HmacSha256 = "HS256"
	HmacSha384 = "HS384"
	HmacSha512 = "HS512"
	HmacBlake2b256 = "Blake2b256"
	HmacBlake2b384 = "Blake2b384"
	HmacBlake2b512 = "Blake2b512"
)

// SigningMethodHMAC implements the HMAC-SHA family of signing methods
// Expects key type of []byte for both signing and validation
type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}

// Specific instances for HS256 and company
var (
	SigningMethodHS256  *SigningMethodHMAC
	SigningMethodHS384  *SigningMethodHMAC
	SigningMethodHS512  *SigningMethodHMAC
	SigningMethodBlake2b256  *SigningMethodHMAC
	SigningMethodBlake2b384  *SigningMethodHMAC
	SigningMethodBlake2b512  *SigningMethodHMAC
	ErrSignatureInvalid = errors.New("signature is invalid")
)

func init() {
	// HS256
	SigningMethodHS256 = &SigningMethodHMAC{HmacSha256, crypto.SHA256}
	RegisterSigningMethod(SigningMethodHS256.Alg(), func() SigningMethod {
		return SigningMethodHS256
	})

	// HS384
	SigningMethodHS384 = &SigningMethodHMAC{HmacSha384, crypto.SHA384}
	RegisterSigningMethod(SigningMethodHS384.Alg(), func() SigningMethod {
		return SigningMethodHS384
	})

	// HS512
	SigningMethodHS512 = &SigningMethodHMAC{HmacSha512, crypto.SHA512}
	RegisterSigningMethod(SigningMethodHS512.Alg(), func() SigningMethod {
		return SigningMethodHS512
	})

	SigningMethodBlake2b256 = &SigningMethodHMAC{HmacBlake2b256, crypto.BLAKE2b_256}
	RegisterSigningMethod(SigningMethodBlake2b256.Alg(), func() SigningMethod {
		return SigningMethodBlake2b256
	})

	SigningMethodBlake2b512 = &SigningMethodHMAC{HmacBlake2b384, crypto.BLAKE2b_384}
	RegisterSigningMethod(SigningMethodBlake2b512.Alg(), func() SigningMethod {
		return SigningMethodBlake2b384
	})

	SigningMethodBlake2b512 = &SigningMethodHMAC{HmacBlake2b512, crypto.BLAKE2b_512}
	RegisterSigningMethod(SigningMethodBlake2b512.Alg(), func() SigningMethod {
		return SigningMethodBlake2b512
	})
}

// Alg implements SigningMethod
func (m *SigningMethodHMAC) Alg() string {
	return m.Name
}

// Verify the signature of HSXXX tokens.  Returns nil if the signature is valid.
// Key must be []byte
func (m *SigningMethodHMAC) Verify(signingString, signature string, key interface{}) error {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return NewInvalidKeyTypeError("[]byte", key)
	}

	// Decode signature, for comparison
	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}

	// Can we use the specified hashing method?
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hasher := hmac.New(m.Hash.New, keyBytes)
	hasher.Write([]byte(signingString))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrSignatureInvalid
	}

	// No validation errors.  Signature is good.
	return nil
}

// Sign implements the Sign method from SigningMethod
// Key must be []byte
func (m *SigningMethodHMAC) Sign(signingString string, key interface{}) (string, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return "", NewInvalidKeyTypeError("[]byte", key)
	}

	if !m.Hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := hmac.New(m.Hash.New, keyBytes)
	hasher.Write([]byte(signingString))

	return EncodeSegment(hasher.Sum(nil)), nil
}
