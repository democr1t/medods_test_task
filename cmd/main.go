package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"log/slog"
	"medods_test_task/internal/handlers"
	"medods_test_task/internal/middlewares"
	"medods_test_task/models"
	"os"
)

func init() {
	//err := godotenv.Load()
	//
	//if err != nil {
	//	log.Fatal("Error loading .env file: ", err)
	//}
}

func main() {
	// Подключение к PostgreSQL
	dsn := os.Getenv("DSN")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	slog.SetLogLoggerLevel(slog.LevelDebug)
	// Автоматическая миграция с явным указанием внешних ключей
	err = db.AutoMigrate(&models.User{}, &models.RefreshTokens{})

	if err != nil {
		log.Fatal(err)
	}
	tokenMaker := &handlers.JWTMaker{SecretKey: os.Getenv("SECRET")}

	r := gin.Default()
	r.POST("/users", handlers.CreateUserHandler(db))
	r.GET("/users", handlers.ListUsersHandler(db))
	r.GET("/users/myid", middlewares.CreateAuthMiddleware(db), handlers.GetMyIDHandler(db))

	r.GET("/tokens/:user_id", handlers.CreateGetTokensHandler(db, tokenMaker))
	r.GET("/logout", handlers.CreateLogoutHandler(db))

	//r.GET("/users/:id", handlers.GetUserHandler(db))
	if err := r.Run(":" + os.Getenv("PORT")); err != nil {
		log.Fatal(err)
	}
}
