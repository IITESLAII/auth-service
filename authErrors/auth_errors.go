package authErrors

import (
	"errors"
	"net/http"
)

var (
	ErrUserExists   = errors.New("user already exists")
	ErrBadRequest   = errors.New("bad request")
	ErrNotFound     = errors.New("user not found")
	ErrInternal     = errors.New("internal error")
	ErrUnauthorized = errors.New("invalid email or password")
)

func ParseErrorToHttpStatus(err error) int {
	switch {
	case errors.Is(err, ErrUserExists):
		return http.StatusConflict
	case errors.Is(err, ErrBadRequest):
		return http.StatusBadRequest
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInternal):
		return http.StatusInternalServerError
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
