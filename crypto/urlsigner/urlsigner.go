package urlsigner

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"hash"
	"net/url"
	"strconv"
	"time"
)

const (
	paramExpireAt   = "expireAt"
	paramRequestUri = "requestUri"
	paramSignature  = "signature"
)

// URLSigner create and verify signed url
type URLSigner struct {
	secret string
	hashFn func() hash.Hash
}

func NewURLSigner(secret string, hashFn func() hash.Hash) *URLSigner {
	return &URLSigner{secret: secret, hashFn: hashFn}
}

func (s *URLSigner) Sign(rawUrl string, expireAt time.Time) (string, error) {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}

	expireAtStr := fmt.Sprintf("%d", expireAt.Unix())
	q := u.Query()
	q.Add(paramExpireAt, expireAtStr)

	u.RawQuery = q.Encode()

	signature, err := s.generateHmac(expireAtStr, u.RequestURI())
	if err != nil {
		return "", err
	}

	q.Add(paramSignature, signature)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func (s *URLSigner) Verify(rawUrl string) error {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return err
	}

	expireAt, err := strconv.ParseInt(u.Query().Get(paramExpireAt), 10, 64)
	if err != nil {
		return errors.New("invalid provided expire parameter")
	}

	if time.Now().Unix() > expireAt {
		return errors.New("url signature expired")
	}

	signature := u.Query().Get(paramSignature)
	q := u.Query()
	q.Del(paramSignature)
	u.RawQuery = q.Encode()

	generatedSignature, err := s.generateHmac(fmt.Sprintf("%d", expireAt), u.RequestURI())
	if err != nil {
		return err
	}

	if generatedSignature != signature {
		return errors.New("invalid signature")
	}

	return nil
}

func (s *URLSigner) generateHmac(expireAt string, requestURI string) (string, error) {
	data, err := json.Marshal(map[string]interface{}{
		paramExpireAt:   expireAt,
		paramRequestUri: requestURI,
	})
	if err != nil {
		return "", err
	}

	h := hmac.New(s.hashFn, []byte(s.secret))
	h.Write(data)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
