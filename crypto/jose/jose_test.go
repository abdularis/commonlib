package jose

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const certificate = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAoWLaEyfjTNqWNJeFhWiS5mIMgu5WpZADPqEfAkeYtxjDiD0Q\nHGjHjzU6lO1gZ5c1hHOYbq/DeoQjCwII6/AduLEsH92Lz5VFRYopkPS6pMz6A51g\nb35Z/gGr3qNTJZ36b3Yg98bxRQu/eHhUOvEWRO5OfP3GWQ1OLW5baWPy0EdDcVPB\nz3jEEFUhKAuPQRTLaj9B5OtgiG9tY8Jvc+xla2aN+yE/G3/KtulblJhQAuiq7129\nIHtkTNIwUm7z5VnkKzR0IkHWcbijIRG/6JRXRcqUbAttWK9hIc7DWgtjeTBjoy6k\nZSUcYUW0fChSEzmroyXAizuMeZbtvzqCcTnsuwIDAQABAoIBAQCgvlDvW39ugRmy\n8GixZGNMzMQhdTsgVLymmNzF7IITfLrk680sPsDlxuK+i2DGTTmk324ocTCGyy4M\nPM6eEd/Ioc+NPaGP9OG2TdLw6pEsrG0pRItVAcio0wlZC9w5T4ytkD9uC90sJHNl\njpR20MKZjbLnk+0HrdT8MzshUcf74ipGGwSBJyLV0ZAxaczPa0j985rh/+DIiegZ\nwMjM61jXitQEJ23HjiXrTmWzOcECI4Y1yQ+sbMz29dXVAktGJ0uipz83uze8+dsI\nvRmZIkVsjKqkelgH2qx6DOQrKbG+zsfRkYtPBTs6If56miZ1mVoJTan/s2OjJaoA\nEMPh6CIBAoGBAMsavqJtWmiNmd0Pf+oyEQG3GtRdhpru4wS7X0ByF9oI4aetopTY\nmvpmHTh3shozGhgsFozy1qZaJoBtC5/EuBMNNLvG5v+BTXT+/vW3kgrVVmTYNRPO\nzc3TrXVu/9KZtrNJczLlsG4Gr0P/38GKzZp4PMEqjB5R2aQ41zOY+lbBAoGBAMtq\nsEBTZ8YWBHRqpQie6dbvWPoQhUfVZoGF+1sAz1xb3nm4O6A9u6UHYUGOMdJe62Ou\nJnV6il3FOrxjOwLlr2EaSRD6YeqoQEqQWqjY6PQj9GaalDXbcbVb/gPbxjGCHlj0\nn2QhUIdjpmwbPWAbfZ9cq9X1QO6XpaRc6mwfT757AoGBAJx9vuTn3QEyGZt6ldSd\nPv1TWBjI9y3pYoIC3SGKx1X4AeZwoxSM0NyeUWVw1InbVf/J+JYhhcInNANAAfTY\nXfxP8JG+b73uov/CejBZgO1X83lAHaVlcq1krAIPxI1AYsVBksFkuMwN2n1Kad12\nVXTvr+AmKFA0QL2IDkhzVnABAoGAMsUFCnkGrIzwPbIkUJuBF5ETbw5ShZRAilFL\nY/I2zwFq7IxL7Xma7NyDrJ3112CzdWSQ2r9j63V/bGeD4fw7ooux8tfbOnsV2MZg\nqkXBFrYmmLk6BpsnrTExm/rtY4vrUR507cPW2oPHlLHTxrn1x6GUjckxlJsqz3QV\nWjkSaSMCgYEAngQ+pnPFF4b+XDv81e4P5ZUO9AEve2ER3r7YptRtm2nUJlHH+nEN\nOTkjG0V3aecDkp4nv+ZC7kxYQd4Nr8bFOQLNghmIHEm7KI1ZOV2mfO5Uq46PEwk0\nraRLtAtyFlzxHxqbzmTM2PH75CCGK0Vjn2SIjnoj8GsS+rwEHzC8Whw=\n-----END RSA PRIVATE KEY-----"
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
