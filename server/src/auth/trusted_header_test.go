package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/markbates/goth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"scrumlr.io/server/auth"
	"scrumlr.io/server/common"
	"scrumlr.io/server/identifiers"
	"scrumlr.io/server/users"
)

// mockUserService is a minimal mock implementing users.UserService for testing.
type mockUserService struct {
	mock.Mock
}

func (m *mockUserService) Create(ctx context.Context, id, name, avatarUrl string, accountType common.AccountType) (*users.User, error) {
	args := m.Called(ctx, id, name, avatarUrl, accountType)
	if u, ok := args.Get(0).(*users.User); ok {
		return u, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *mockUserService) Get(ctx context.Context, id uuid.UUID) (*users.User, error) {
	return nil, nil
}
func (m *mockUserService) GetBoardUsers(ctx context.Context, boardID uuid.UUID) ([]*users.User, error) {
	return nil, nil
}
func (m *mockUserService) GetExistingUserIDs(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (m *mockUserService) Update(ctx context.Context, body users.UserUpdateRequest) (*users.User, error) {
	return nil, nil
}
func (m *mockUserService) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockUserService) IsUserAvailableForKeyMigration(ctx context.Context, id uuid.UUID) (bool, error) {
	return false, nil
}
func (m *mockUserService) SetKeyMigration(ctx context.Context, id uuid.UUID) (*users.User, error) {
	return nil, nil
}

// mockAuth is a minimal mock implementing auth.Auth. Its Verifier always
// returns 401 so that tests for the JWT fallback path can verify the fallback occurs.
type mockAuth struct{}

func (mockAuth) Sign(claims map[string]any) (string, error) { return "", nil }
func (mockAuth) Verifier() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
}
func (mockAuth) Authenticator() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}
func (mockAuth) Exists(accountType common.AccountType) bool { return false }
func (mockAuth) ExtractUserInformation(accountType common.AccountType, gothUser *goth.User) (*auth.UserInformation, error) {
	return nil, nil
}

// captureHandler records the user ID placed in context by the middleware.
func captureHandler(t *testing.T, gotID *uuid.UUID) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value(identifiers.UserIdentifier)
		if val != nil {
			if id, ok := val.(uuid.UUID); ok {
				*gotID = id
			}
		}
		w.WriteHeader(http.StatusOK)
	})
}

// TestTrustedHeaderOrJWT_NoHeader_FallsBackToJWT verifies that when the subject
// header is absent the JWT handler is invoked (which returns 401 in tests
// because there is no real JWT).
func TestTrustedHeaderOrJWT_NoHeader_FallsBackToJWT(t *testing.T) {
	svc := &mockUserService{}
	jwtAuth := mockAuth{}

	var gotID uuid.UUID
	mw := auth.TrustedHeaderOrJWT("X-Forwarded-User", "X-Forwarded-Name", svc, jwtAuth)
	handler := mw(captureHandler(t, &gotID))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, uuid.Nil, gotID)
	svc.AssertNotCalled(t, "Create")
}

// TestTrustedHeaderOrJWT_Disabled_FallsBackToJWT verifies that when
// subjectHeader is empty (feature disabled) the JWT path is used even if the
// header is present in the request.
func TestTrustedHeaderOrJWT_Disabled_FallsBackToJWT(t *testing.T) {
	svc := &mockUserService{}
	jwtAuth := mockAuth{}

	var gotID uuid.UUID
	mw := auth.TrustedHeaderOrJWT("", "", svc, jwtAuth)
	handler := mw(captureHandler(t, &gotID))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "alice")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, uuid.Nil, gotID)
	svc.AssertNotCalled(t, "Create")
}

// TestTrustedHeaderOrJWT_ValidSubject_SetsUserInContext verifies that a valid
// subject header resolves a user and places its ID in the request context.
func TestTrustedHeaderOrJWT_ValidSubject_SetsUserInContext(t *testing.T) {
	expectedID := uuid.New()
	svc := &mockUserService{}
	svc.On("Create", mock.Anything, "alice@example.com", "Alice", "", common.TrustedHeader).
		Return(&users.User{ID: expectedID}, nil)

	jwtAuth := mockAuth{}
	var gotID uuid.UUID
	mw := auth.TrustedHeaderOrJWT("X-Forwarded-User", "X-Forwarded-Name", svc, jwtAuth)
	handler := mw(captureHandler(t, &gotID))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "alice@example.com")
	req.Header.Set("X-Forwarded-Name", "Alice")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, expectedID, gotID)
	svc.AssertExpectations(t)
}

// TestTrustedHeaderOrJWT_BlankName_FallsBackToSubject verifies that when the
// name header is blank, the subject is used as the display name.
func TestTrustedHeaderOrJWT_BlankName_FallsBackToSubject(t *testing.T) {
	expectedID := uuid.New()
	svc := &mockUserService{}
	svc.On("Create", mock.Anything, "alice", "alice", "", common.TrustedHeader).
		Return(&users.User{ID: expectedID}, nil)

	jwtAuth := mockAuth{}
	var gotID uuid.UUID
	mw := auth.TrustedHeaderOrJWT("X-Forwarded-User", "X-Forwarded-Name", svc, jwtAuth)
	handler := mw(captureHandler(t, &gotID))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "alice")
	// X-Forwarded-Name intentionally absent
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, expectedID, gotID)
	svc.AssertExpectations(t)
}

// TestTrustedHeaderOrJWT_ServiceError_Returns401 verifies that a provisioning
// error results in a 401 response.
func TestTrustedHeaderOrJWT_ServiceError_Returns401(t *testing.T) {
	svc := &mockUserService{}
	svc.On("Create", mock.Anything, "alice", "alice", "", common.TrustedHeader).
		Return((*users.User)(nil), errors.New("db error"))

	jwtAuth := mockAuth{}
	var gotID uuid.UUID
	mw := auth.TrustedHeaderOrJWT("X-Forwarded-User", "X-Forwarded-Name", svc, jwtAuth)
	handler := mw(captureHandler(t, &gotID))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "alice")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, uuid.Nil, gotID)
}

// TestTrustedHeaderOrJWT_RepeatRequests_SameUser verifies that two requests
// with the same subject resolve the same user ID.
func TestTrustedHeaderOrJWT_RepeatRequests_SameUser(t *testing.T) {
	expectedID := uuid.New()
	svc := &mockUserService{}
	svc.On("Create", mock.Anything, "bob", "bob", "", common.TrustedHeader).
		Return(&users.User{ID: expectedID}, nil)

	jwtAuth := mockAuth{}
	mw := auth.TrustedHeaderOrJWT("X-Forwarded-User", "X-Forwarded-Name", svc, jwtAuth)

	for i := 0; i < 2; i++ {
		var gotID uuid.UUID
		handler := mw(captureHandler(t, &gotID))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-User", "bob")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, expectedID, gotID)
	}
	svc.AssertNumberOfCalls(t, "Create", 2) // service is called each time; idempotency is in the DB layer
}
