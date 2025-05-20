package main

import (
	"github.com/gin-gonic/gin"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"log/slog"
	"medods_test_task/docs"
	"medods_test_task/handlers"
	"medods_test_task/middlewares"
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

// @contact.name   Dmitry
// @contact.email  d.kruteevz@gmail.com

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html
// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name access
// @description JWT access token
func main() {

	docs.SwaggerInfo.Title = "Medods auth test task"
	docs.SwaggerInfo.Description = "Path of auth service for medods test task."
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = "localhost"
	docs.SwaggerInfo.Schemes = []string{"http"}

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
	r.GET("/tokens/refresh", handlers.CreateRefreshTokensHandler(db, tokenMaker))
	r.GET("/logout", handlers.CreateLogoutHandler(db))

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	//r.GET("/users/:id", handlers.GetUserHandler(db))
	if err := r.Run(":" + os.Getenv("PORT")); err != nil {
		log.Fatal(err)
	}
}
