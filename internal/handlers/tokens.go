package handlers

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"log/slog"
	"medods_test_task/models"
	"net/http"
	"time"
)

type myClaims struct {
	Ip        string `json:"ip"`
	USERAGENT string `json:"useragent"`
	jwt.RegisteredClaims
}

type TokenMaker interface {
	CreateToken(userID string, ip string, USERAGENT string, duration time.Duration) (string, error)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type JWTMaker struct {
	SecretKey string
}

func (maker *JWTMaker) CreateToken(userID string, ip string, USERAGENT string, duration time.Duration) (string, error) {

	claims := &myClaims{
		Ip:        ip,
		USERAGENT: USERAGENT,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString([]byte(maker.SecretKey))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// CreateGetTokensHandler создает пару токенов для пользователя
func CreateGetTokensHandler(db *gorm.DB, tokenMaker TokenMaker) gin.HandlerFunc {
	slog.Debug("tokens handler initialized")
	return func(c *gin.Context) {

		userID := c.Param("user_id")
		uuidUserID, err := uuid.Parse(userID)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			return
		}

		var user models.User
		if err := db.First(&user, "id = ?", uuidUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			}
			return
		}

		var existedToken models.RefreshTokens

		if err := db.First(&existedToken, "user_id = ?", uuidUserID).Error; err == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "tokens already exists, you need to /logout first"})
			return
		}

		accessToken, err := tokenMaker.CreateToken(userID, c.ClientIP(), c.Request.UserAgent(), 15*time.Minute)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access token"})
			return
		}

		refreshToken, err := tokenMaker.CreateToken(userID, c.ClientIP(), c.Request.UserAgent(), 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
			return
		}

		refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

		if err != nil {
			slog.Error("Failed to hash refresh token", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
		}

		tokens := models.RefreshTokens{
			RefreshToken: string(refreshTokenHash),
			UserID:       user.ID,
		}

		c.SetCookie("access", accessToken, 15*60, "/", "", true, true)
		c.SetCookie("refresh", refreshToken, 3600*60, "/", "", true, true)
		c.SetSameSite(http.SameSiteLaxMode)

		if err := db.Create(&tokens).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
			return
		}

		// Формируем ответ
		response := TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}

		c.JSON(http.StatusOK, response)
	}
}

func CreateLogoutHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.SetCookie("access", "", 0, "/", "", false, true)
		c.JSON(200, gin.H{"message": "logout successfully"})
	}
}
