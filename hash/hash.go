package hash

import (
	"golang.org/x/crypto/bcrypt"
	"mssngr/authErrors"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return string(bytes), authErrors.ErrInternal
	}
	return string(bytes), nil
}

func CheckPasswordHash(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
