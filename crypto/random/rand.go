/*
 * Created on 6/7/21, 9:05 PM by abdularis
 */

package common

import (
	"math/rand"
	"time"
)

const randomCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

func String(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = randomCharset[seededRand.Intn(len(randomCharset))]
	}
	return string(b)
}
