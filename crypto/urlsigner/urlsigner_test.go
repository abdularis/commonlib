package urlsigner

import (
	"crypto/sha256"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestURLSigner_SignVerify(t *testing.T) {
	sampleUrls := []struct {
		URL          string
		ShouldExpire bool
	}{
		{
			URL:          "https://example.com/public/files/users/8239482384.jpg",
			ShouldExpire: false,
		},
		{
			URL:          "https://example.com/public/files/users/8239482384.jpg?param=test&param2=test2",
			ShouldExpire: false,
		},
		{
			URL:          "https://example.com/public/files/users/8239482384.jpg",
			ShouldExpire: true,
		},
	}

	signer := NewURLSigner("123456", sha256.New)
	for _, v := range sampleUrls {
		expireAt := time.Now()
		if v.ShouldExpire {
			expireAt = expireAt.Add(-time.Hour)
		}

		signedUrl, err := signer.Sign(v.URL, expireAt)
		require.NoError(t, err)

		t.Logf("signed url: %s\n", signedUrl)

		err = signer.Verify(signedUrl)

		if v.ShouldExpire {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}
