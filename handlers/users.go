package handlers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"log/slog"
	"medods_test_task/models"
	"net/http"
	"os"
)

// @Summary Create new user
// @Description Creates a new user with auto-generated UUID
// @Tags Users
// @Accept json
// @Produce json
// @Success 201 {object} models.User "Successfully created user"
// @Failure 500 {object} map[string]string "error: Failed to create user"
// @Router /users [post]
func CreateUserHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User
		user.ID = uuid.New()

		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		c.JSON(http.StatusCreated, user)
	}
}

// @Summary Get all users
// @Description Retrieves list of all registered users
// @Tags Users
// @Produce json
// @Success 200 {array} models.User "List of users"
// @Failure 500 {object} map[string]string "error: Failed to fetch users"
// @Router /users [get]
func ListUsersHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var users []models.User

		if err := db.Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
			return
		}

		c.JSON(http.StatusOK, users)
	}
}

// @Summary Get current user ID
// @Description Returns authenticated user's ID and session info from JWT token
// @Tags Users
// @Produce json
// @Security CookieAuth
// @Success 200 {object} map[string]string "user: User UUID, ip: Client IP, useragent: User-Agent"
// @Failure 400 {object} map[string]string "error: Access cookie not present | Your token is broken"
// @Failure 401 {object} map[string]string "error: Invalid token"
// @Router /users/myid [get]
func GetMyIDHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		t, err := c.Cookie("access")

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Access cookie not present"})
		}

		token, err := jwt.ParseWithClaims(t, &MyClaims{}, func(token *jwt.Token) (interface{}, error) {

			return []byte(os.Getenv("SECRET")), nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Your token is broken"})
		}

		if claims, ok := token.Claims.(*MyClaims); ok {
			fmt.Println(claims)
			c.JSON(http.StatusOK, gin.H{
				"user":      claims.Subject,
				"ip":        claims.Ip,
				"useragent": claims.USERAGENT,
			})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			slog.Debug(err.Error())
		}
	}
}
