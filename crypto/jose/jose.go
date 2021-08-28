package jose

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
)

// TokenClaims store all jwt claims
type TokenClaims map[string]interface{}

type Signature interface {
	Sign(claims TokenClaims) ([]byte, error)
	Verify(token []byte) (TokenClaims, error)
}

type Encryption interface {
	Encrypt(token []byte) ([]byte, error)
	Decrypt(token []byte) ([]byte, error)
}

// Jose is main interface to interact with the package
type Jose interface {
	GenerateJWS(claims TokenClaims) ([]byte, error)
	GenerateJWE(claims TokenClaims) ([]byte, error)
	VerifyJWS(token []byte) (TokenClaims, error)
	VerifyJWE(token []byte) (TokenClaims, error)
}

type signatureImpl struct {
	privateKey *rsa.PrivateKey
	signAlgo   jwa.SignatureAlgorithm
}

type encryptionImpl struct {
	privateKey     *rsa.PrivateKey
	signAlgo       jwa.SignatureAlgorithm
	keyEncAlgo     jwa.KeyEncryptionAlgorithm
	contentEncAlgo jwa.ContentEncryptionAlgorithm
}

func parsePEMCertificate(pemPrivateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemPrivateKey)
	if block == nil {
		return nil, errors.New("no PEM data found in the input bytes")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func NewSignature(privateKey *rsa.PrivateKey) Signature {
	return &signatureImpl{
		privateKey: privateKey,
		signAlgo:   jwa.RS256,
	}
}

func (s *signatureImpl) Sign(claims TokenClaims) ([]byte, error) {
	token := jwt.New()
	for key, val := range claims {
		if err := token.Set(key, val); err != nil {
			return nil, err
		}
	}

	signed, err := jwt.Sign(token, s.signAlgo, s.privateKey)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func (s *signatureImpl) Verify(token []byte) (TokenClaims, error) {
	t, err := jwt.Parse(token, jwt.WithVerify(s.signAlgo, s.privateKey.PublicKey))
	if err != nil {
		return nil, err
	}

	claimMap, err := t.AsMap(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error converting claims to map: %v", claimMap)
	}

	if err = jwt.Validate(t); err != nil {
		return claimMap, err
	}

	return claimMap, nil
}

func NewEncryption(privateKey *rsa.PrivateKey) Encryption {
	return &encryptionImpl{
		privateKey:     privateKey,
		signAlgo:       jwa.RS256,
		keyEncAlgo:     jwa.RSA1_5,
		contentEncAlgo: jwa.A128CBC_HS256,
	}
}

func (e *encryptionImpl) Encrypt(token []byte) ([]byte, error) {
	return jwe.Encrypt(
		token,
		e.keyEncAlgo,
		&e.privateKey.PublicKey,
		e.contentEncAlgo,
		jwa.NoCompress)
}

func (e *encryptionImpl) Decrypt(token []byte) ([]byte, error) {
	return jwe.Decrypt(token, e.keyEncAlgo, e.privateKey)
}

type utilsImpl struct {
	signature  Signature
	encryption Encryption
}

func NewJose(certificate string) (Jose, error) {
	privateKey, err := parsePEMCertificate([]byte(certificate))
	if err != nil {
		return nil, err
	}

	return &utilsImpl{
		signature:  NewSignature(privateKey),
		encryption: NewEncryption(privateKey),
	}, nil
}

func (u *utilsImpl) GenerateJWS(claims TokenClaims) ([]byte, error) {
	return u.signature.Sign(claims)
}

func (u *utilsImpl) GenerateJWE(claims TokenClaims) ([]byte, error) {
	signed, err := u.signature.Sign(claims)
	if err != nil {
		return nil, err
	}

	return u.encryption.Encrypt(signed)
}

func (u *utilsImpl) VerifyJWS(token []byte) (TokenClaims, error) {
	return u.signature.Verify(token)
}

func (u *utilsImpl) VerifyJWE(token []byte) (TokenClaims, error) {
	decrypted, err := u.encryption.Decrypt(token)
	if err != nil {
		return nil, err
	}
	return u.signature.Verify(decrypted)
}
