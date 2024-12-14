package authgrpc

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type mockAuthService struct {
	mock.Mock
}

func newMockAuthService() *mockAuthService {
	return &mockAuthService{}
}

func (m *mockAuthService) Login(ctx context.Context, email string, password string) (token string, err error) {
	args := m.Called(email, password)
	return args.String(0), args.Error(1)
}

func (m *mockAuthService) Logout(ctx context.Context, token string) (bool, error) {
	args := m.Called(token)
	return args.Bool(0), args.Error(1)
}

func (m *mockAuthService) Register(ctx context.Context, email string, password string, username string, firstName string, lastName string) (userID int64, err error) {
	args := m.Called(email, password, username, firstName, lastName)
	return int64(args.Int(0)), args.Error(1)
}
