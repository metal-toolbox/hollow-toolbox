//go:build testtools
// +build testtools

package ginjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	testKeySize = 2048

	// TestPrivRSAKey1 provides an RSA key used to sign tokens
	TestPrivRSAKey1, _ = rsa.GenerateKey(rand.Reader, testKeySize)
	// TestPrivRSAKey1ID is the ID of this signing key in tokens
	TestPrivRSAKey1ID = "testKey1"
	// TestPrivRSAKey2 provides an RSA key used to sign tokens
	TestPrivRSAKey2, _ = rsa.GenerateKey(rand.Reader, testKeySize)
	// TestPrivRSAKey2ID is the ID of this signing key in tokens
	TestPrivRSAKey2ID = "testKey2"
	// TestPrivRSAKey3 provides an RSA key used to sign tokens
	TestPrivRSAKey3, _ = rsa.GenerateKey(rand.Reader, testKeySize)
	// TestPrivRSAKey3ID is the ID of this signing key in tokens
	TestPrivRSAKey3ID = "testKey3"
	// TestPrivRSAKey4 provides an RSA key used to sign tokens
	TestPrivRSAKey4, _ = rsa.GenerateKey(rand.Reader, testKeySize)
	// TestPrivRSAKey4ID is the ID of this signing key in tokens
	TestPrivRSAKey4ID = "testKey4"
	keyMap            sync.Map
)

func init() {
	keyMap.Store(TestPrivRSAKey1ID, TestPrivRSAKey1)
	keyMap.Store(TestPrivRSAKey2ID, TestPrivRSAKey2)
	keyMap.Store(TestPrivRSAKey3ID, TestPrivRSAKey3)
	keyMap.Store(TestPrivRSAKey4ID, TestPrivRSAKey4)
}

// TestHelperMustMakeSigner will return a JWT signer from the given key
func TestHelperMustMakeSigner(alg jose.SignatureAlgorithm, kid string, k interface{}) jose.Signer {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}

	return sig
}

// TestHelperJoseJWKSProvider returns a JWKS
func TestHelperJoseJWKSProvider(keyIDs ...string) jose.JSONWebKeySet {
	jwks := make([]jose.JSONWebKey, len(keyIDs))

	for idx, keyID := range keyIDs {
		rawKey, found := keyMap.Load(keyID)
		if !found {
			panic("Failed finding private key to create test JWKS provider. Fix the test.")
		}

		privKey := rawKey.(*rsa.PrivateKey)

		jwks[idx] = jose.JSONWebKey{
			KeyID: keyID,
			Key:   &privKey.PublicKey,
		}
	}

	return jose.JSONWebKeySet{
		Keys: jwks,
	}
}

// TestHelperJWKSProvider returns a url for a webserver that will return JSONWebKeySets
func TestHelperJWKSProvider(keyIDs ...string) string {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	keySet := TestHelperJoseJWKSProvider(keyIDs...)

	r.GET("/.well-known/jwks.json", func(c *gin.Context) {
		c.JSON(http.StatusOK, keySet)
	})

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	s := &http.Server{
		Handler: r,
	}

	go func() {
		if err := s.Serve(listener); err != nil {
			panic(err)
		}
	}()

	return fmt.Sprintf("http://localhost:%d/.well-known/jwks.json", listener.Addr().(*net.TCPAddr).Port)
}

// TestHelperGetToken will return a signed token
func TestHelperGetToken(signer jose.Signer, cl jwt.Claims, key string, value interface{}) string {
	sc := map[string]interface{}{}

	sc[key] = value

	raw, err := jwt.Signed(signer).Claims(cl).Claims(sc).CompactSerialize()
	if err != nil {
		panic(err)
	}

	return raw
}
