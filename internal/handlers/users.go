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

// CreateUserHandler создает нового пользователя
func CreateUserHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User

		// Генерируем новый UUID для пользователя
		user.ID = uuid.New()

		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		c.JSON(http.StatusCreated, user)
	}
}

// ListUsersHandler возвращает список всех пользователей
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

// GetUserHandler возвращает пользователя по ID
func GetUserHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("id")

		uuidUserID, err := uuid.Parse(userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			return
		}

		var user models.User
		if err := db.First(&user, "id = ?", uuidUserID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			}
			return
		}

		c.JSON(http.StatusOK, user)
	}
}

func GetMyIDHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		t, err := c.Cookie("access")

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Access cookie not present"})
		}

		token, err := jwt.ParseWithClaims(t, &MyClaims{}, func(token *jwt.Token) (interface{}, error) {
			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
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
