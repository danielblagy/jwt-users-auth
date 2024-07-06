// Code generated by mockery v2.42.0. DO NOT EDIT.

package mocks

import (
	context "context"

	auth "github.com/danielblagy/jwt-users-auth/auth"

	mock "github.com/stretchr/testify/mock"
)

// AuthService is an autogenerated mock type for the AuthService type
type AuthService struct {
	mock.Mock
}

// Authorize provides a mock function with given fields: ctx, tokens
func (_m *AuthService) Authorize(ctx context.Context, tokens *auth.TokenPair) (*auth.TokenPair, string, error) {
	ret := _m.Called(ctx, tokens)

	if len(ret) == 0 {
		panic("no return value specified for Authorize")
	}

	var r0 *auth.TokenPair
	var r1 string
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, *auth.TokenPair) (*auth.TokenPair, string, error)); ok {
		return rf(ctx, tokens)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *auth.TokenPair) *auth.TokenPair); ok {
		r0 = rf(ctx, tokens)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*auth.TokenPair)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *auth.TokenPair) string); ok {
		r1 = rf(ctx, tokens)
	} else {
		r1 = ret.Get(1).(string)
	}

	if rf, ok := ret.Get(2).(func(context.Context, *auth.TokenPair) error); ok {
		r2 = rf(ctx, tokens)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// LogIn provides a mock function with given fields: ctx, username, password
func (_m *AuthService) LogIn(ctx context.Context, username string, password string) (*auth.TokenPair, error) {
	ret := _m.Called(ctx, username, password)

	if len(ret) == 0 {
		panic("no return value specified for LogIn")
	}

	var r0 *auth.TokenPair
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (*auth.TokenPair, error)); ok {
		return rf(ctx, username, password)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *auth.TokenPair); ok {
		r0 = rf(ctx, username, password)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*auth.TokenPair)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, username, password)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LogOut provides a mock function with given fields: ctx, tokens
func (_m *AuthService) LogOut(ctx context.Context, tokens *auth.TokenPair) error {
	ret := _m.Called(ctx, tokens)

	if len(ret) == 0 {
		panic("no return value specified for LogOut")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *auth.TokenPair) error); ok {
		r0 = rf(ctx, tokens)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewAuthService creates a new instance of AuthService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuthService(t interface {
	mock.TestingT
	Cleanup(func())
}) *AuthService {
	mock := &AuthService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
