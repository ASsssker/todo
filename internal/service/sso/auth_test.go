package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ASsssker/todo/internal/domain/models"
	"github.com/ASsssker/todo/internal/storage"
	fake "github.com/brianvoe/gofakeit/v7"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthLogin_HappyPath(t *testing.T) {
	password := fakePassword()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := models.User{
		ID:           fake.Uint64(),
		Email:        fake.Email(),
		PasswordHash: string(passwordHash),
	}

	mockProvider := newMockUserProvider()
	mockProvider.On("GetUserByEmail", user.Email).Return(user, nil)

	tokenCreateTime := time.Now()
	auth := newAuthService(mockProvider)
	token, err := auth.Login(context.TODO(), user.Email, password)
	require.NoError(t, err)

	var claims jwt.MapClaims
	_, err = jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(auth.secret), nil
	})
	require.NoError(t, err)
	assert.Equal(t, float64(user.ID), claims["uid"])
	assert.Equal(t, user.Email, claims["email"])
	assert.InDelta(t, tokenCreateTime.Add(auth.tokenTTL).Unix(), claims["exp"].(float64), 1)

}

func TestAuthLogin_BadPathServiceReturnError(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		providerErr error
		expecErr    string
	}{
		{
			name:        "Non-existent email",
			email:       fake.Email(),
			providerErr: storage.ErrUserNotFound,
			expecErr:    ErrInvalidCredentials.Error(),
		},
		{
			name:        "Provider return undefined error",
			email:       fake.Email(),
			providerErr: errors.New("undefined error"),
			expecErr:    "undefined error",
		},
	}

	mockProvider := newMockUserProvider()
	for _, tt := range tests {
		mockProvider.On("GetUserByEmail", tt.email).Return(models.User{}, tt.providerErr)
	}

	auth := newAuthService(mockProvider)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := auth.Login(context.TODO(), tt.email, "")
			require.Empty(t, token)
			require.ErrorContains(t, err, tt.expecErr)
		})
	}
}

func TestAuthLogin_BadPathIncorrectPassowrd(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(fakePassword()), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := models.User{
		ID:           fake.Uint64(),
		Email:        fake.Email(),
		PasswordHash: string(passwordHash),
	}

	mockProvider := newMockUserProvider()
	mockProvider.On("GetUserByEmail", user.Email).Return(user, nil)

	auth := newAuthService(mockProvider)
	token, err := auth.Login(context.TODO(), user.Email, fakePassword())
	require.Empty(t, token)
	require.ErrorContains(t, err, ErrInvalidCredentials.Error())
}

func newAuthService(userProvider UserProvider) *Auth {
	return &Auth{
		log:          slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{})),
		userProvider: userProvider,
		tokenTTL:     time.Hour,
		secret:       "secret",
	}
}

func TestAuthRegister_HappyPath(t *testing.T) {
	expectID := fake.Int64()
	email := fake.Email()
	password := fakePassword()
	username := fake.Username()

	mockProvider := newMockUserProvider()
	mockProvider.On("SaveUser", email, username).Return(int(expectID), nil)

	auth := newAuthService(mockProvider)
	id, err := auth.Register(context.TODO(), email, password, username)
	require.NoError(t, err)
	require.Equal(t, id, expectID)

}

func TestAuthRegister_BadPathServiceReturnError(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		password    string
		username    string
		providerErr error
		expectErr   string
	}{
		{
			name:        "User already exists",
			email:       fake.Email(),
			password:    fakePassword(),
			username:    fake.Username(),
			providerErr: storage.ErrUserAlreadyExists,
			expectErr:   ErrUserAlreadyExists.Error(),
		},
		{
			name:        "Provider return undefined error",
			email:       fake.Email(),
			password:    fakePassword(),
			username:    fake.Username(),
			providerErr: errors.New("undefined error"),
			expectErr:   "undefined error",
		},
	}

	mockProvider := newMockUserProvider()
	for _, tt := range tests {
		mockProvider.On("SaveUser", tt.email, tt.username).Return(0, tt.providerErr)
	}

	auth := newAuthService(mockProvider)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := auth.Register(context.TODO(), tt.email, tt.password, tt.username)
			require.Empty(t, id)
			require.ErrorContains(t, err, tt.expectErr)
		})
	}
}

func fakePassword() string {
	return fake.Password(true, true, true, false, false, 10)
}
