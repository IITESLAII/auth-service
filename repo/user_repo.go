package repo

import (
	"database/sql"
	"fmt"
	"log"
	"mssngr/authErrors"
	"mssngr/model"
	"os"
)

func CreatePostgresDatabase() (*sql.DB, error) {
	url := os.Getenv("POSTGRES_URL")
	if url == "" {
		return nil, fmt.Errorf("environment variable POSTGRES_URL is not set. Please define it before running the application")
	}

	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

type UserRepository interface {
	CreateUser(email, hashedPassword string) (*model.User, error)
	GetByEmail(email string) (*model.User, error)
	GetById(email string) (*model.User, error)
	ChangePassword(id string, password string) error
}
type pgUserRepository struct {
	db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) UserRepository {
	return &pgUserRepository{
		db: db,
	}
}

func (p *pgUserRepository) CreateUser(email, hashedPassword string) (*model.User, error) {
	var user model.User
	err := p.db.QueryRow(
		"INSERT INTO users (email, hashed_password) VALUES ($1, $2) RETURNING id",
		email, hashedPassword,
	).Scan(&user.Id)
	if err != nil {
		log.Printf("failed while creating user: %v", err)
		return nil, authErrors.ErrInternal
	}
	user.Email = email
	user.Password = hashedPassword

	return &user, nil
}
func (p *pgUserRepository) GetByEmail(email string) (*model.User, error) {
	row := p.db.QueryRow("SELECT id, email, hashed_password FROM	users where email = $1", email)
	var user model.User
	err := row.Scan(&user.Id, &user.Email, &user.Password)
	if err != nil {
		return nil, authErrors.ErrNotFound
	}
	return &user, nil
}
func (p *pgUserRepository) GetById(id string) (*model.User, error) {
	row := p.db.QueryRow("SELECT id, email, hashed_password FROM users where id = $1", id)
	var user model.User
	err := row.Scan(&user.Id, &user.Email, &user.Password)
	if err != nil {
		return nil, authErrors.ErrNotFound
	}
	return &user, nil
}
func (p *pgUserRepository) ChangePassword(id string, password string) error {
	_, err := p.db.Exec("UPDATE users SET hashed_password = $1 WHERE id = $2", password, id)
	if err != nil {
		return err
	}
	return nil
}
