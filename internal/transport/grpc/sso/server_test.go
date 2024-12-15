package authgrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ASsssker/todo/internal/domain/models"
	"github.com/ASsssker/todo/internal/lib/jwt"
	auth "github.com/ASsssker/todo/internal/service/sso"
	ssov1 "github.com/ASsssker/todo/protos/gen/go/sso"
	fake "github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerLogin_HappyPath(t *testing.T) {
	email := fake.Email()
	password := fakePassword()
	token, err := jwt.NewToken(models.User{
		ID:    fake.Uint64(),
		Email: email,
	}, time.Hour, fake.Name())
	require.NoError(t, err)

	mockService := newMockAuthService()
	mockService.On("Login", email, password).Return(token, nil)

	srv := serverAPI{auth: mockService}
	resp, err := srv.Login(context.TODO(), &ssov1.LoginRequest{Email: email, Password: password})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, token, resp.Token)
}

func TestServerLogin_BadPath(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		password   string
		serviceErr error
		expectErr  string
	}{
		{
			name:       "Empty password and email",
			email:      "",
			password:   "",
			serviceErr: nil,
			expectErr:  "email is required",
		},
		{
			name:       "Empty email",
			email:      "",
			password:   fakePassword(),
			serviceErr: nil,
			expectErr:  "email is required",
		},
		{
			name:       "Empty password",
			email:      fake.Email(),
			password:   "",
			serviceErr: nil,
			expectErr:  "password is required",
		},
		{
			name:       "Invalid email or password",
			email:      fake.Email(),
			password:   fakePassword(),
			serviceErr: auth.ErrInvalidCredentials,
			expectErr:  "invalid email or password",
		},
		{
			name:       "Service undefined error",
			email:      fake.Email(),
			password:   fakePassword(),
			serviceErr: errors.New("undefined error"),
			expectErr:  "failed to login",
		},
	}

	mockService := newMockAuthService()
	for _, tt := range tests {
		mockService.On("Login", tt.email, tt.password).Return("", tt.serviceErr)
	}
	srv := serverAPI{auth: mockService}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := srv.Login(context.TODO(), &ssov1.LoginRequest{Email: tt.email, Password: tt.password})
			require.Nil(t, resp)
			require.ErrorContains(t, err, tt.expectErr)

		})
	}
}

func TestServerLogout_HappyPath(t *testing.T) {
	correctToken, err := jwt.NewToken(models.User{
		ID:    fake.Uint64(),
		Email: fake.Email(),
	}, time.Hour, fake.Name())
	require.NoError(t, err)

	incorrectToken, err := jwt.NewToken(models.User{
		ID:    fake.Uint64(),
		Email: fake.Email(),
	}, time.Hour, fake.Name())
	require.NoError(t, err)

	mockService := newMockAuthService()
	mockService.On("Logout", correctToken).Return(true, nil)
	mockService.On("Logout", incorrectToken).Return(false, nil)

	srv := serverAPI{auth: mockService}

	resp, err := srv.Logout(context.TODO(), &ssov1.LogoutRequest{Token: correctToken})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, true, resp.Success)

	resp, err = srv.Logout(context.TODO(), &ssov1.LogoutRequest{Token: incorrectToken})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, false, resp.Success)
}

func TestServerLogout_BadPath(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		serviceErr error
		expectErr  string
	}{
		{
			name:       "Empty token",
			token:      "",
			serviceErr: nil,
			expectErr:  "token is required",
		},
		{
			name:       "Token user not found",
			token:      "fakeToken1",
			serviceErr: auth.ErrUserNotFound,
			expectErr:  "user not found",
		},
		{
			name:       "Service undefined error",
			token:      "fakeToken2",
			serviceErr: errors.New("undefined error"),
			expectErr:  "failed to logout",
		},
	}

	mockServie := newMockAuthService()
	for _, tt := range tests {
		mockServie.On("Logout", tt.token).Return(false, tt.serviceErr)
	}

	srv := serverAPI{auth: mockServie}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := srv.Logout(context.TODO(), &ssov1.LogoutRequest{Token: tt.token})
			require.Nil(t, resp)
			require.ErrorContains(t, err, tt.expectErr)
		})
	}
}

func TestServerRegister_HappyPath(t *testing.T) {
	tests := []struct {
		name         string
		email        string
		password     string
		username     string
		firstName    string
		lastName     string
		ExpectUserID int64
	}{
		{
			name:         "All fields fill",
			email:        fake.Email(),
			password:     fakePassword(),
			username:     fake.Username(),
			firstName:    fake.FirstName(),
			lastName:     fake.LastName(),
			ExpectUserID: fake.Int64(),
		},
		{
			name:         "Required fields are filled in",
			email:        fake.Email(),
			password:     fakePassword(),
			username:     fake.Username(),
			firstName:    "",
			lastName:     "",
			ExpectUserID: fake.Int64(),
		},
	}

	mockService := newMockAuthService()
	for _, tt := range tests {
		mockService.On("Register", tt.email, tt.password, tt.username, tt.firstName, tt.lastName).Return(int(tt.ExpectUserID), nil)
	}

	srv := serverAPI{auth: mockService}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := srv.Register(context.TODO(), &ssov1.RegisterRequest{
				Email:     tt.email,
				Password:  tt.password,
				Username:  tt.username,
				FirstName: tt.firstName,
				LastName:  tt.lastName,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tt.ExpectUserID, resp.GetUserId())
		})
	}
}

func TestServerRegister_BadPath(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		password   string
		username   string
		firstName  string
		lastName   string
		serviceErr error
		expectErr  string
	}{
		{
			name:       "Empty email",
			email:      "",
			password:   fakePassword(),
			username:   fake.UserAgent(),
			firstName:  fake.FirstName(),
			lastName:   fake.LastName(),
			serviceErr: nil,
			expectErr:  "email is required",
		},
		{
			name:       "Empty password",
			email:      fake.Email(),
			password:   "",
			username:   fake.Username(),
			firstName:  fake.FirstName(),
			lastName:   fake.LastName(),
			serviceErr: nil,
			expectErr:  "password is required",
		},
		{
			name:       "Empty username",
			email:      fake.Email(),
			password:   fakePassword(),
			username:   "",
			firstName:  fake.FirstName(),
			lastName:   fake.LastName(),
			serviceErr: nil,
			expectErr:  "username is required",
		},
		{
			name:       "All required fields are empty",
			email:      "",
			password:   "",
			username:   "",
			firstName:  fake.FirstName(),
			lastName:   fake.LastName(),
			serviceErr: nil,
			expectErr:  "email is required",
		},
		{
			name:       "User already exists",
			email:      fake.Email(),
			password:   fakePassword(),
			username:   fake.Username(),
			firstName:  fake.FirstName(),
			lastName:   fake.LastName(),
			serviceErr: auth.ErrUserAlreadyExists,
			expectErr:  "user already exists",
		},
		{
			name:       "Service undefined error",
			email:      fake.Email(),
			password:   fakePassword(),
			username:   fake.Username(),
			firstName:  fake.FirstName(),
			lastName:   fake.LastName(),
			serviceErr: errors.New("undefined error"),
			expectErr:  "failed to register user",
		},
	}

	mockService := newMockAuthService()
	for _, tt := range tests {
		mockService.On("Register", tt.email, tt.password, tt.username, tt.firstName, tt.lastName).Return(0, tt.serviceErr)
	}

	srv := serverAPI{auth: mockService}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := srv.Register(context.TODO(), &ssov1.RegisterRequest{
				Email:     tt.email,
				Password:  tt.password,
				Username:  tt.username,
				FirstName: tt.firstName,
				LastName:  tt.lastName,
			})
			require.Nil(t, resp)
			require.ErrorContains(t, err, tt.expectErr)
		})
	}
}

func fakePassword() string {
	return fake.Password(true, true, true, false, false, 10)
}
