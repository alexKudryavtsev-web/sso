package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userId int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int64) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
)

func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:          log,
		userSaver:    userSaver,
		userProvider: userProvider,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

func (a *Auth) Login(ctx context.Context, email string, password string, appID int64) (string, error) {
	const op = "services.auth.Login"

	a.log.With(slog.String("op", op), slog.String("email", email))

	user, err := a.userProvider.User(ctx, email)

	if errors.Is(err, storage.ErrUserNotFound) {
		return "", fmt.Errorf("%s: %w", "op", ErrInvalidCredentials)
	}

	if err != nil {
		a.log.Error("failed to find user", err)

		return "", fmt.Errorf("%s: %w", "op", err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		return "", fmt.Errorf("%s: %w", "op", ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)

	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)

	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "services.auth.RegisterNewUser"

	a.log.With(slog.String("op", op), slog.String("email", email))

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		a.log.Error("failed to generate password hash", err)

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	userId, err := a.userSaver.SaveUser(ctx, email, passHash)

	if errors.Is(err, storage.ErrUserExists) {
		return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
	}

	if err != nil {
		a.log.Error("failed to save user ", err)

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return userId, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userId int64) (bool, error) {
	const op = "servies.auth.IsAdmin"

	a.log.With(slog.String("op", op), slog.Int64("uid", userId))

	isAdmin, err := a.userProvider.IsAdmin(ctx, userId)

	if errors.Is(err, storage.ErrUserNotFound) {
		a.log.Info("user not foud")

		return false, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	if err != nil {
		a.log.Error("failed to get isAdmin", sl.Err(err))

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}
