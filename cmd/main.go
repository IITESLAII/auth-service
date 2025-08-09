package main

import (
	"context"
	"database/sql"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"log"
	"mssngr/handler"
	repo2 "mssngr/repo"
	"mssngr/service"
	"net/http"
	"os"
)

func main() {
	ctx := context.Background()

	db := mustPostgresDatabase()
	defer db.Close()

	redisDb := mustRedisDatabase()
	defer redisDb.Close()

	userRepo := repo2.NewPostgresUserRepository(db)
	redisRepo := repo2.NewRedis(redisDb, ctx)
	userService := service.NewUserService(userRepo, redisRepo)
	userHandler := handler.NewUserHandler(userService)

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://zany-space-memory-q7qvw76rw9qrf4rw4-3000.app.github.dev"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type", "Set-Cookie"},
		AllowCredentials: true,
	}))
	r.GET("/ping", userHandler.CheckJWTAccessToken(), func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})
	r.POST("/register", userHandler.RegisterHandler())
	r.POST("/login", userHandler.LoginHandler())
	r.POST("/refresh", userHandler.RefreshJWTAccessToken())
	r.POST("/logout", userHandler.LogOutHandler())
	r.POST("/reset-password", userHandler.SendPasswordResetEmail())
	r.POST("/reset-password-code", userHandler.CheckPasswordResetCode())
	r.POST("/change-password", userHandler.PasswordReset())

	host := os.Getenv("HOST")
	if host == "" {
		host = "localhost:8080"
	}
	r.Run(host)
}

// mustPostgresDatabase — close service if connection failed
func mustPostgresDatabase() *sql.DB {
	db, err := repo2.CreatePostgresDatabase()
	if err != nil {
		log.Fatalf("Не удалось подключиться к Postgres: %v", err)
	}
	return db
}

// mustRedisDatabase — close service if connection failed
func mustRedisDatabase() *redis.Client {
	client, err := repo2.CreateRedisDatabase()
	if err != nil {
		log.Fatalf("Не удалось подключиться к Redis: %v", err)
	}
	return client
}
