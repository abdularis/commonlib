package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/abdularis/commonlib/crypto/keygen"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwt"
)

// TokenClaims store all jwt claims
type TokenClaims map[string]interface{}

type (
	Signature struct {
		privateKey interface{}
		signAlgo   jwa.SignatureAlgorithm
	}

	Encryption struct {
		privateKey     interface{}
		keyEncAlgo     jwa.KeyEncryptionAlgorithm
		contentEncAlgo jwa.ContentEncryptionAlgorithm
	}

	Jose struct {
		signature  *Signature
		encryption *Encryption
	}

	Config struct {
		SignatureAlgorithm      jwa.SignatureAlgorithm
		KeyEncryptionAlgorithm  jwa.KeyEncryptionAlgorithm
		ContentEncryptAlgorithm jwa.ContentEncryptionAlgorithm
	}
)

func NewSignature(privateKey interface{}, signAlgorithm jwa.SignatureAlgorithm) *Signature {
	return &Signature{
		privateKey: privateKey,
		signAlgo:   signAlgorithm,
	}
}

func (s *Signature) Sign(claims TokenClaims) ([]byte, error) {
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

func (s *Signature) Verify(token []byte) (jwt.Token, error) {
	t, err := jwt.Parse(token, jwt.WithVerify(s.signAlgo, getPublicKey(s.privateKey)))
	if err != nil {
		return nil, err
	}

	if err = jwt.Validate(t); err != nil {
		return t, err
	}

	return t, nil
}

func NewEncryption(
	privateKey interface{},
	keyEncAlgo jwa.KeyEncryptionAlgorithm,
	contentEncAlgo jwa.ContentEncryptionAlgorithm) *Encryption {
	return &Encryption{
		privateKey:     privateKey,
		keyEncAlgo:     keyEncAlgo,
		contentEncAlgo: contentEncAlgo,
	}
}

func (e *Encryption) Encrypt(token []byte) ([]byte, error) {
	return jwe.Encrypt(
		token,
		e.keyEncAlgo,
		getPublicKey(e.privateKey),
		e.contentEncAlgo,
		jwa.NoCompress)
}

func (e *Encryption) Decrypt(token []byte) ([]byte, error) {
	return jwe.Decrypt(token, e.keyEncAlgo, e.privateKey)
}

func getPublicKey(privateKey interface{}) interface{} {
	var ptr interface{}
	switch v := privateKey.(type) {
	case rsa.PrivateKey:
		ptr = &v
	case ecdsa.PrivateKey:
		ptr = &v
	default:
		ptr = v
	}

	switch rawKey := ptr.(type) {
	case *rsa.PrivateKey:
		return rawKey.PublicKey
	case *ecdsa.PrivateKey:
		return rawKey.PublicKey
	default:
		return rawKey
	}
}

func NewJose(pemCertificate string, config Config) (*Jose, error) {
	privateKey, err := keygen.ParseKey([]byte(pemCertificate))
	if err != nil {
		return nil, err
	}

	return &Jose{
		signature:  NewSignature(privateKey, config.SignatureAlgorithm),
		encryption: NewEncryption(privateKey, config.KeyEncryptionAlgorithm, config.ContentEncryptAlgorithm),
	}, nil
}

func (u *Jose) GenerateJWS(claims TokenClaims) ([]byte, error) {
	return u.signature.Sign(claims)
}

func (u *Jose) GenerateJWE(claims TokenClaims) ([]byte, error) {
	signed, err := u.signature.Sign(claims)
	if err != nil {
		return nil, err
	}
	return u.encryption.Encrypt(signed)
}

func (u *Jose) VerifyJWS(token []byte) (jwt.Token, error) {
	return u.signature.Verify(token)
}

func (u *Jose) VerifyJWE(token []byte) (jwt.Token, error) {
	decrypted, err := u.encryption.Decrypt(token)
	if err != nil {
		return nil, err
	}
	return u.signature.Verify(decrypted)
}
