package auth

import (
	"context"

	"github.com/ASsssker/todo/internal/domain/models"
	"github.com/stretchr/testify/mock"
)

type mockUserProvider struct {
	mock.Mock
}

func newMockUserProvider() *mockUserProvider {
	return &mockUserProvider{}
}

func (m *mockUserProvider) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	args := m.Called(email)
	user, ok := args.Get(0).(models.User)
	if !ok {
		panic("auth_mock.GetUserByEmail: error convert interface to models.User")
	}
	return user, args.Error(1)
}

func (m *mockUserProvider) SaveUser(ctx context.Context, email string, username string, passwordHash []byte) (uuid int64, err error) {
	args := m.Called(email, username)
	return int64(args.Int(0)), args.Error(1)
}
