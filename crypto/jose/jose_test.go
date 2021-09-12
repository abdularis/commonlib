package jose

import (
	"github.com/abdularis/commonlib/crypto/keygen"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// pkcs8 rsa certificate
const certificate = "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqcfCMrjiVLrQ0\n5JsIUpSVYdKHxcOlAnJEjyGxSiNi9lbD2IoJIRpEMgEb1bHXD7Qj7VPVXshXB6Pb\nQ8BLl0OlRz5mhxDeeuuQ275IW3rJNueoNGJ05L1tRHmiNJUSBRivQqKGmJKkeh/x\nLBByZ8QPeh/TwUKFUHgl6r9s5SNQ0XJWiYDNOt0Zg3egEvnclxqTrrPSjO8BvFvf\ngujO/iUtjyWhh8CVKrigfx/qyDmpV0Ia/SJ/gcWmVH0DbQSjodFR37yJR1T6v3QV\nDHtPRZoIPS1F/nitesHfzLfFUE7eWk1H495ouhxnqQW6dsAjv6j88wc2BTPAKBbo\nVSSu/85lAgMBAAECggEAEEyC/0Dtwj5MFz7BIIOdF8fZ9QfRVKcuPCYfx69aQO1j\nkKjVUlgrBdhuSLYfonwq8sCQIrhEmiXt4lrROalGW7i7W9yQnWXNvvV0dcDhtfod\nHvWbcKgrARbqNrumgamhGalal1phs37GLS7Uh8wqcHxyLLKvZMY0JxQSqBwlS2YD\n93kmpWTTK9idrelXawLzpiGqPF0LM20X1bxSOemdPltS9wVte1rw+/G1kanPfgR2\nWzh4bVgNBXtqCmp7TaoUP3gsynvMiFK+0xYFK3t9s55TkNJ54Nai4WXMjUd+1OGo\nJw8mFpcAC9ZKzcHGV72B2YgvZrsdszxNfDboV2SJYQKBgQDZ9NQhrqizCFXywxYd\nnGEuRa2wH88R1Du45Y5do4afJltO/BWCqfONAzUVy3U6tcEQNtY+Xw0B+D3DxXXm\ngKeGZwY2e/4laeHvtVEKZ3F6bYGtvhwF06eFXsaWpZM1AzeSrcGa2Y3/LK5oa9MP\nGnOzVBLxGVTmi69LAiU4KPMfrQKBgQDIMh1eMtARctsv4EE6Wizoyc3bTCies1ov\n6Xyc439mqEmOkyFCQfYVj4khTy8AbdlquZgt8sR8ilQENOqWrP2Qa3cwkbGiwTgS\nssjJxbFagQmNiTClSVJUJ3SWPAuGvmYg0U7yUk3J3UxzEULAyG9Pho+TcJytL3z5\ndyTUxzVgmQKBgCPZ3brcm+s3B8wywsSEIIgX9gXudYUdP+Wd/NjyOQacrJBFbtRb\nWDBtwqGfId1SYDtmib8gq2cTijVVmZsctnGpKKB1rMxCqmNfk8D+WvAkaxxFFR7w\nPbH2cPv+qEQkD1QVOK9b8btzggyzD7iARV/OCH+YBxsVBvRzmeOu+K7RAoGAPvj8\noe/r4UE2z1WETx2keMlZ9rx7HoieOuoAJ72sCpevI6kGUjg7d0bCRPcKeuES/e5J\nf1KZGe/NQ9F9ZU4fKLmVMXLy5JZQ1Bjm7glAo45pedsIsUViH1SV6NgUbBsiNvqA\nEdtv2qrA7IUmcUvbL7HNIfzPW+7PKg2fSUsscCkCgYEAmAzedtXXafGAkKHBijHC\ndj9Mk7rVMFCjOl57VXb0fjbkSOmDOM2uPL5kB2zl2X2XcR3q4w1orf/KF8gzs74c\nGA6MiRopDifnDlybpSei6TSMbdHXQ1V8m8xtd+Q0fV9YdKBiryX60/Wj4xaJF3Lg\nS9I/VM1f0dW81kB3rsijrdU=\n-----END RSA PRIVATE KEY-----"

// pkcs8 elliptic curve certificate
const ecCertificate = "-----BEGIN EC PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHkM7YE2Rv6R0fpO1\ni/njTkSbcrB0bxcCtB10ufumyR+hRANCAAS8C6OglBWlVxcMl/Mhu+gUh0QcD1Ch\nEMgc0sGmKWNCIUDWWC8Kxk82n2cxxVmFD9Xm2XzkHJhEgL5ydJyKL2WP\n-----END EC PRIVATE KEY-----"

func TestJose_GenerateJWEVerifyJWE(t *testing.T) {
	u, err := NewJose(ecCertificate, Config{
		SignatureAlgorithm:      jwa.ES256,
		KeyEncryptionAlgorithm:  jwa.ECDH_ES_A256KW,
		ContentEncryptAlgorithm: jwa.A128CBC_HS256,
	})
	require.NoError(t, err)

	token, err := u.GenerateJWE(TokenClaims{
		"iss": "my-app",
		"sub": "28129",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	require.NotNil(t, token)

	t.Logf("token = %s\n", string(token))

	claims, err := u.VerifyJWE(token)
	t.Logf("claims = %+v\n", claims)
	require.NoError(t, err)
}

func TestSignature_Sign_WithCertificate(t *testing.T) {
	privateKey, err := keygen.ParseKey([]byte(certificate))
	require.NoError(t, err)

	s := NewSignature(privateKey, jwa.RS256)
	testSignAndVerify(t, s, privateKey)
}

func TestSignature_Sign_WithSecretKey(t *testing.T) {
	secret := []byte("this-is-secret-key")
	s := NewSignature(secret, jwa.HS256)
	testSignAndVerify(t, s, secret)
}

func testSignAndVerify(t *testing.T, signer *Signature, key interface{}) {
	issuer := "my-app"
	subject := "aris@gmail.com"
	userID := "12923"

	signed, err := signer.Sign(TokenClaims{
		"iss": issuer,
		"sub": subject,
		"uid": userID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	tkn, err := signer.Verify(signed)
	require.NoError(t, err)
	require.Equal(t, issuer, tkn.Issuer())
	require.Equal(t, subject, tkn.Subject())
	require.Equal(t, userID, tkn.PrivateClaims()["uid"])

	t.Logf("signed token: %s\n", signed)
}
