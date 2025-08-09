package handler

import (
	"github.com/gin-gonic/gin"
	"log"
	"mssngr/authErrors"
	"mssngr/service"
	token2 "mssngr/token"
	"net/http"
)

type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}
type PasswordInput struct {
	Password string `json:"password" binding:"required"`
}
type EmailInput struct {
	Email string `json:"email" binding:"required,email"`
}
type EmailWithCodeInput struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required"`
}

type UserHandler struct {
	service service.UserServiceInterface
}

func NewUserHandler(s service.UserServiceInterface) *UserHandler {
	return &UserHandler{service: s}
}

func (h *UserHandler) LoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var input LoginInput
		if err := c.ShouldBindJSON(&input); err != nil {
			err = authErrors.ErrBadRequest
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		accessToken, refreshToken, err := h.service.Login(input.Email, input.Password)
		if err != nil {
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.SetCookie(accessToken.Name, accessToken.Value, accessToken.MaxAge, accessToken.Path, accessToken.Domain, accessToken.Secure, accessToken.HttpOnly)
		c.SetCookie(refreshToken.Name, refreshToken.Value, refreshToken.MaxAge, refreshToken.Path, refreshToken.Domain, refreshToken.Secure, refreshToken.HttpOnly)
		c.String(http.StatusOK, "Login success")
	}
}

func (h *UserHandler) RegisterHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var input LoginInput
		if err := c.ShouldBindJSON(&input); err != nil {
			err = authErrors.ErrBadRequest
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		accessToken, refreshToken, err := h.service.Register(input.Email, input.Password)
		if err != nil {
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.SetCookie(accessToken.Name, accessToken.Value, accessToken.MaxAge, accessToken.Path, accessToken.Domain, accessToken.Secure, accessToken.HttpOnly)
		c.SetCookie(refreshToken.Name, refreshToken.Value, refreshToken.MaxAge, refreshToken.Path, refreshToken.Domain, refreshToken.Secure, refreshToken.HttpOnly)
		c.String(http.StatusOK, "Register success")
	}
}

func (h *UserHandler) CheckJWTAccessToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, err := c.Cookie(token2.AccessCookieName)
		if err != nil {
			err = authErrors.ErrUnauthorized
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		isBlackList, err := h.service.IsBlackListed(accessToken)
		if err != nil || isBlackList {
			c.SetCookie(token2.AccessCookieName, "", -1, "/", "", true, true)
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		jwt, err := token2.ParseJWT(accessToken)
		if err != nil || !jwt.Valid {
			err = authErrors.ErrUnauthorized
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *UserHandler) LogOutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Work with access token
		accessToken, err := c.Cookie(token2.AccessCookieName)
		if err != nil {
			err = authErrors.ErrUnauthorized
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		claims, err := token2.ParseJWTWithClaims(accessToken)
		if err != nil {
			c.SetCookie(token2.AccessCookieName, "", -1, "/", "", true, true)
			err = authErrors.ErrInternal
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		timeExp, err := claims.GetExpirationTime()
		if err != nil {
			c.SetCookie(token2.AccessCookieName, "", -1, "/", "", true, true)
			err = authErrors.ErrInternal
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		err = h.service.AddToBlackList(accessToken, timeExp)
		if err != nil {
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Work with refresh token
		refreshToken, err := c.Cookie(token2.RefreshCookieName)
		if err != nil {
			err = authErrors.ErrUnauthorized
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		claims, err = token2.ParseJWTWithClaims(refreshToken)
		if err != nil {
			c.SetCookie(token2.RefreshCookieName, "", -1, "/", "", true, true)
			err = authErrors.ErrInternal
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		timeExp, err = claims.GetExpirationTime()
		if err != nil {
			c.SetCookie(token2.RefreshCookieName, "", -1, "/", "", true, true)
			err = authErrors.ErrInternal
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		err = h.service.AddToBlackList(refreshToken, timeExp)
		if err != nil {
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.SetCookie(token2.AccessCookieName, "", -1, "/", "", true, true)
		c.SetCookie(token2.RefreshCookieName, "", -1, "/", "", true, true)
		c.String(http.StatusOK, "LogOutSuccess")
	}
}

func (h *UserHandler) RefreshJWTAccessToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, err := c.Cookie(token2.AccessCookieName)
		if err == nil {
			jwtAccess, err := token2.ParseJWT(accessToken)
			if err == nil && jwtAccess.Valid {
				c.Next()
				return
			}
		}

		refreshToken, err := c.Cookie(token2.RefreshCookieName)
		if err != nil {
			err = authErrors.ErrUnauthorized
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		claims, err := token2.ParseJWTWithClaims(refreshToken)
		if err != nil {
			err = authErrors.ErrUnauthorized
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		accessCookie, err := service.GenerateAccessToken(claims.ID)
		if err != nil {
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.SetCookie(accessCookie.Name, accessCookie.Value, accessCookie.MaxAge, accessCookie.Path, accessCookie.Domain, accessCookie.Secure, accessCookie.HttpOnly)
		c.String(http.StatusOK, "Refresh success")
	}
}

func (h *UserHandler) SendPasswordResetEmail() gin.HandlerFunc {
	return func(c *gin.Context) {
		var input EmailInput
		if err := c.ShouldBindJSON(&input); err != nil {
			err = authErrors.ErrBadRequest
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		log.Println(input.Email)

		err := h.service.SendPasswordResetMail(input.Email)
		if err != nil {
			log.Println(err)
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			return
		}

		log.Println("ok")
		c.String(http.StatusOK, "Send password reset email success")
	}
}

func (h *UserHandler) CheckPasswordResetCode() gin.HandlerFunc {
	return func(c *gin.Context) {
		var input EmailWithCodeInput
		if err := c.ShouldBindJSON(&input); err != nil {
			err = authErrors.ErrBadRequest
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		log.Println("Получены почта и код")
		cookie, err := h.service.CheckPasswordResetCode(input.Email, input.Code)
		if err != nil {
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		log.Println("Код верен")
		c.SetCookie(cookie.Name, cookie.Value, cookie.MaxAge, cookie.Path, cookie.Domain, cookie.Secure, cookie.HttpOnly)
		c.String(http.StatusOK, "Code check success")
	}
}

func (h *UserHandler) PasswordReset() gin.HandlerFunc {
	return func(c *gin.Context) {
		var input PasswordInput
		if err := c.ShouldBindJSON(&input); err != nil {
			err = authErrors.ErrBadRequest
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		cookie, err := c.Cookie("resetToken")
		if err != nil {
			err = authErrors.ErrUnauthorized
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
		}
		us, err := token2.ParseJWTWithClaims(cookie)
		if err != nil {
			err = authErrors.ErrInternal
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
		}
		isBlackListed, err := h.service.IsBlackListed(cookie)
		if err != nil || isBlackListed {
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		h.service.AddToBlackList(cookie, us.ExpiresAt)
		err = h.service.ChangePassword(input.Password, cookie)
		if err != nil {
			c.JSON(authErrors.ParseErrorToHttpStatus(err), gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.String(http.StatusOK, "Password change success")
	}
}
