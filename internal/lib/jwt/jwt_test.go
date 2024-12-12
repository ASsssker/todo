package jwt

import (
	"testing"
	"time"

	"github.com/ASsssker/todo/internal/domain/models"
	fake "github.com/brianvoe/gofakeit/v7"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewToken(t *testing.T) {
	user := models.User{
		ID:    fake.Uint64(),
		Email: fake.Email(),
	}

	duration := time.Hour
	secret := []byte(fake.Name())

	token, err := NewToken(user, duration, string(secret))
	require.NoError(t, err)
	require.NotEmpty(t, token)
	tokenCreateTime := time.Now()

	var claims jwt.MapClaims
	_, err = jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	require.NoError(t, err)

	assert.Equal(t, float64(user.ID), claims["uid"], "incorrect user id")
	assert.Equal(t, user.Email, claims["email"], "incorrect user email")
	assert.InDelta(t, tokenCreateTime.Add(duration).Unix(), claims["exp"].(float64), 1)

}
