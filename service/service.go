package service

import (
	"fmt"
	"log"
	"mssngr/authErrors"
	"mssngr/hash"
	repo2 "mssngr/repo"
	"mssngr/token"
	"net/smtp"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sethvargo/go-password/password"
)

// the service returns errors in Errors format
// they must be parsed via the Errors func

type GinCookie struct {
	Name     string
	Value    string
	MaxAge   int
	Path     string
	Domain   string
	Secure   bool
	HttpOnly bool
}

type UserServiceInterface interface {
	Register(email, password string) (*GinCookie, *GinCookie, error)
	Login(email, password string) (*GinCookie, *GinCookie, error)
	AddToBlackList(str string, exp *jwt.NumericDate) error
	RemoveFromBlackList(str string) error
	IsBlackListed(str string) (bool, error)
	SendPasswordResetMail(email string) error
	CheckPasswordResetCode(email string, code string) (*GinCookie, error)
	ChangePassword(newPassword string, tokenReset string) error
}

type UserService struct {
	psql  repo2.UserRepository
	redis repo2.RedisRepository
}

func NewUserService(r repo2.UserRepository, re repo2.RedisRepository) *UserService {
	return &UserService{psql: r, redis: re}
}

func (s *UserService) Register(email, password string) (*GinCookie, *GinCookie, error) {
	_, err := s.psql.GetByEmail(email)
	if err == nil {
		return nil, nil, authErrors.ErrUserExists
	}
	hashPassword, err := hash.HashPassword(password)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}
	user, err := s.psql.CreateUser(email, hashPassword)
	if err != nil {
		return nil, nil, err
	}
	accessToken, refreshToken, err := generateAccessRefreshTokens(user.Id)
	if err != nil {
		return nil, nil, err
	}
	return accessToken, refreshToken, nil
}

func (s *UserService) Login(email, password string) (*GinCookie, *GinCookie, error) {
	user, err := s.psql.GetByEmail(email)
	if err != nil {
		return nil, nil, err
	}

	if hash.CheckPasswordHash(user.Password, password) {
		accessToken, refreshToken, err := generateAccessRefreshTokens(user.Id)
		if err != nil {
			return nil, nil, err
		}
		return accessToken, refreshToken, nil
	}

	return nil, nil, authErrors.ErrUnauthorized
}

func (s *UserService) AddToBlackList(str string, exp *jwt.NumericDate) error {
	expUnix := exp.Unix()
	now := time.Now().Unix()
	duration := time.Duration(expUnix-now) * time.Second
	err := s.redis.AddToMap(str, true, duration)
	if err != nil {
		return authErrors.ErrInternal
	}
	return nil
}
func (s *UserService) RemoveFromBlackList(str string) error {
	err := s.redis.RemoveFromMap(str)
	if err != nil {
		return authErrors.ErrInternal
	}
	return nil
}
func (s *UserService) IsBlackListed(str string) (bool, error) {
	res, err := s.redis.IsExist(str)
	if err != nil {
		return false, authErrors.ErrInternal
	}
	return res, nil
}

const PasswordResetQuery = "password-reset-query"

func (s *UserService) SendPasswordResetMail(email string) error {
	res, err := s.psql.GetByEmail(email)
	if err != nil {
		return authErrors.ErrBadRequest
	}

	if res.Id == "" {
		return nil
	}
	code, err := password.Generate(6, 3, 0, false, true)
	if err != nil {
		return authErrors.ErrInternal
	}
	s.redis.AddToMap(email, code, time.Minute)

	from := os.Getenv("SMTP_EMAIL")
	password := os.Getenv("SMTP_PASSWORD")

	to := []string{email}
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	message := []byte(
		"Subject: Reset password mail\r\n" +
			"To: " + email + "\r\n" +
			"\r\n" +
			"Здравствуйте!\r\n" +
			"Для сброса пароля введите этот код:\r\n" +
			code + "\r\n" +
			"Если вы не запрашивали сброс, просто проигнорируйте это письмо.\r\n")

	log.Println(string(message))
	auth := smtp.PlainAuth("", from, password, smtpHost)

	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		log.Println(err)
		return authErrors.ErrInternal
	}

	return nil
}

func (s *UserService) CheckPasswordResetCode(email string, code string) (*GinCookie, error) {
	res, err := s.redis.GetValue(email)
	if err != nil {
		return nil, err
	}
	log.Println("Код существует")
	str, ok := res.(string)
	if !ok {
		return nil, authErrors.ErrInternal
	}
	if str != code {
		return nil, authErrors.ErrBadRequest
	}
	log.Println("Код правильный")
	user, err := s.psql.GetByEmail(email)
	if err != nil {
		return nil, authErrors.ErrInternal
	}
	log.Println("Пользователь получен")
	t, timeExp, err := token.GenerateJWTResetPassword(user.Id)
	if err != nil {
		log.Println("Ошибка генерации токена сброса пароля:", err)
		return nil, authErrors.ErrInternal
	}
	log.Println("Токен сгенерирован")
	cookie := GinCookie{
		Name:     "resetToken",
		Value:    t,
		MaxAge:   int(timeExp.Seconds()),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	}
	log.Println("CookieOK")
	return &cookie, nil
}

func (s *UserService) ChangePassword(newPassword string, tokenReset string) error {
	claims, err := token.ParseJWTWithClaims(tokenReset)
	if err != nil {
		return authErrors.ErrInternal
	}
	err = s.AddToBlackList(tokenReset, claims.ExpiresAt)
	if err != nil {
		return authErrors.ErrInternal
	}
	user, err := s.psql.GetById(claims.ID)
	if err != nil {
		return authErrors.ErrInternal
	}
	password, err := hash.HashPassword(newPassword)
	if err != nil {
		return authErrors.ErrInternal
	}
	err = s.psql.ChangePassword(user.Id, password)
	if err != nil {
		return authErrors.ErrInternal
	}
	return nil
}

func generateAccessRefreshTokens(id string) (*GinCookie, *GinCookie, error) {
	jwtAccess, jwtRefresh, expAccess, expRefresh, err := token.GenerateJWTTokens(id)
	if err != nil {
		return nil, nil, err
	}
	maxAge := int(expAccess.Seconds())
	var tokenJWTAccess = GinCookie{
		Name:     token.AccessCookieName,
		Value:    jwtAccess,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
	}
	maxAge = int(expRefresh.Seconds())
	var tokenJWTRefresh = GinCookie{
		Name:     token.RefreshCookieName,
		Value:    jwtRefresh,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
	}
	return &tokenJWTAccess, &tokenJWTRefresh, nil
}
func GenerateAccessToken(id string) (*GinCookie, error) {
	jwtAccess, expAccess, err := token.GenerateJWTAccess(id)
	if err != nil {
		return nil, err
	}
	maxAge := int(expAccess.Seconds())
	var tokenJWTAccess = GinCookie{
		Name:     token.AccessCookieName,
		Value:    jwtAccess,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
	}
	return &tokenJWTAccess, nil
}
