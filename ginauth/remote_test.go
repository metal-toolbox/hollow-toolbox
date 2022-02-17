package ginauth_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"go.hollow.sh/toolbox/ginauth"
)

func getNewTestRemoteAuthServer(resp *ginauth.AuthResponseV1, forcedSleep time.Duration) string {
	gin.SetMode(gin.TestMode)

	r := gin.New()

	statusResp := http.StatusUnauthorized

	if resp.Authed {
		statusResp = http.StatusOK
	}

	r.GET("/v1", func(c *gin.Context) {
		time.Sleep(forcedSleep)
		c.JSON(statusResp, resp)
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

	return fmt.Sprintf("http://localhost:%d/v1", listener.Addr().(*net.TCPAddr).Port)
}

func TestRemoteMiddleware(t *testing.T) {
	tests := []struct {
		name             string
		expectedResponse *ginauth.AuthResponseV1
		responseCode     int
		shouldTimeout    bool
	}{
		{
			"test happy path",
			&ginauth.AuthResponseV1{
				AuthMeta: ginauth.AuthMeta{
					Version: "v1",
				},
				Authed:  true,
				Message: "authenticated",
				Details: &ginauth.SuccessAuthDetailsV1{
					Subject: "foo",
				},
			},
			http.StatusOK,
			false,
		},
		{
			"test rejection",
			&ginauth.AuthResponseV1{
				AuthMeta: ginauth.AuthMeta{
					Version: "v1",
				},
				Authed:  false,
				Message: "operation not permitted",
			},
			http.StatusUnauthorized,
			false,
		},
		{
			"test rejection due to timeout",
			&ginauth.AuthResponseV1{
				AuthMeta: ginauth.AuthMeta{
					Version: "v1",
				},
				Authed:  true,
				Message: "operation not permitted",
			},
			// If the server times out we treat it as a rejection
			http.StatusUnauthorized,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverLag := 0 * time.Second
			middlewareTimeout := 0 * time.Second

			if tt.shouldTimeout {
				serverLag = 5 * time.Second
				middlewareTimeout = 1 * time.Second
			}

			authServerURL := getNewTestRemoteAuthServer(tt.expectedResponse, serverLag)
			rm := ginauth.NewRemoteMiddleware(authServerURL, middlewareTimeout)
			r := gin.New()

			// Scopes are kind of irrelevant right now as they are to be
			// handled on the server side. So we can just hard-code them here for now.
			r.Use(rm.AuthRequired([]string{"auth"}))
			r.GET("/", func(c *gin.Context) {
				c.JSON(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "http://test/", nil)

			// We'll be testing explicitly expected responses. It's up to the server to
			// actually validate this token.
			req.Header.Set("Authorization", "bearer foo")

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.responseCode, w.Code)
		})
	}
}
