package handlers

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"log/slog"
	"medods_test_task/models"
	"net/http"
	"time"
)

// TokenMaker интерфейс для создания токенов
type TokenMaker interface {
	CreateToken(userID uuid.UUID, email string, isAdmin bool, duration time.Duration) (string, *jwt.RegisteredClaims, error)
}

// TokenResponse структура ответа с токенами
type TokenResponse struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	SessionID             int       `json:"session_id"`
}

// JWTMaker реализация TokenMaker
type JWTMaker struct {
	SecretKey string
}

func (maker *JWTMaker) CreateToken(userID uuid.UUID, email string, isAdmin bool, duration time.Duration) (string, *jwt.RegisteredClaims, error) {

	claims := &jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString([]byte(maker.SecretKey))

	if err != nil {
		return "", nil, err
	}

	return tokenString, claims, nil
}

// TokensHandler создает пару токенов для пользователя
func TokensHandler(db *gorm.DB, tokenMaker TokenMaker) gin.HandlerFunc {
	slog.Debug("tokens handler initialized")
	return func(c *gin.Context) {
		// Получаем userID из параметров запроса
		userID := c.Param("user_id")

		// Парсим UUID
		uuidUserID, err := uuid.Parse(userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			return
		}

		// Проверяем существование пользователя
		var user models.User
		if err := db.First(&user, "id = ?", uuidUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			}
			return
		}

		// Создаем access token (15 минут)
		accessToken, accessClaims, err := tokenMaker.CreateToken(user.ID, "", false, 15*time.Minute)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access token"})
			return
		}

		// Создаем refresh token (24 часа)
		refreshToken, refreshClaims, err := tokenMaker.CreateToken(user.ID, "", false, 24*time.Hour)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
			return
		}

		// Создаем сессию в базе данных
		session := models.Session{
			RefreshToken: refreshToken,
			UserID:       user.ID,
			ExpiresAt:    refreshClaims.ExpiresAt.Time,
		}

		c.SetCookie("access", accessToken, 15, "/", "", false, true)
		c.SetSameSite(http.SameSiteLaxMode)

		if err := db.Create(&session).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
			return
		}

		// Формируем ответ
		response := TokenResponse{
			AccessToken:           accessToken,
			RefreshToken:          refreshToken,
			AccessTokenExpiresAt:  accessClaims.ExpiresAt.Time,
			RefreshTokenExpiresAt: refreshClaims.ExpiresAt.Time,
			SessionID:             session.ID,
		}

		c.JSON(http.StatusOK, response)
	}
}
