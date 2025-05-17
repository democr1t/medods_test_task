package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"medods_test_task/models"
	"net/http"
	"time"
)

// CreateSessionHandler создает новую сессию для пользователя
func CreateSessionHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			UserID       uuid.UUID `json:"user_id" binding:"required"`
			RefreshToken string    `json:"refresh_token" binding:"required"`
			ExpiresAt    time.Time `json:"expires_at" binding:"required"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Проверяем существование пользователя
		var user models.User
		if err := db.First(&user, "id = ?", request.UserID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		var existedSession models.Session
		if err := db.First(&existedSession, "user_id = ?", request.UserID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Refresh token not found"})
			return
		}

		session := models.Session{
			RefreshToken:  request.RefreshToken,
			LastIP:        c.ClientIP(),
			LastUSERAGENT: c.Request.UserAgent(),
			UserID:        request.UserID,
			ExpiresAt:     request.ExpiresAt,
		}

		if err := db.Create(&session).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
			return
		}

		c.JSON(http.StatusCreated, session)
	}
}

// GetUserSessionsHandler возвращает все сессии пользователя
func GetUserSessionsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")

		// Парсим UUID из строки
		uuidUserID, err := uuid.Parse(userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			return
		}

		var sessions []models.Session
		if err := db.Preload("User").Where("user_id = ?", uuidUserID).Find(&sessions).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch sessions"})
			return
		}

		c.JSON(http.StatusOK, sessions)
	}
}
