package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"io"
)

// RSA create new rsa private key with given bits length
// and return it in PEM format
func RSA(bits int) ([]byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs8PrivateKey,
	}), nil
}

func Elliptic(curve elliptic.Curve, rand io.Reader) ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}

	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: pkcs8PrivateKey,
	}), nil
}

func ParseElliptic(pemPrivateKey []byte) (*ecdsa.PrivateKey, error) {
	key, err := ParseKey(pemPrivateKey)
	if err != nil {
		return nil, err
	}

	if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
		return ecKey, nil
	}
	return nil, errors.New("error provided key is not ecdsa private key")
}

func ParseRSA(pemPrivateKey []byte) (*rsa.PrivateKey, error) {
	key, err := ParseKey(pemPrivateKey)
	if err != nil {
		return nil, err
	}

	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		return rsaKey, nil
	}
	return nil, errors.New("error provided key is not rsa private key")
}

func ParseKey(pemPrivateKey []byte) (interface{}, error) {
	block, _ := pem.Decode(pemPrivateKey)
	if block == nil {
		return nil, errors.New("no PEM data found in the input bytes")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}
