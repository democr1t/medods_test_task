package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"log/slog"
	"medods_test_task/models"
	"net/http"
)

// @Summary Logout user
// @Description Logs out the user by deleting refresh token and clearing cookies
// @Tags Auth
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string "message: logout successfully"
// @Failure 400 {object} map[string]string "error: Failed to parse access token"
// @Failure 401 {object} map[string]string "error: Refresh token not found, you need to login first"
// @Failure 500 {object} map[string]string "error: failed to logout"
// @Router /logout [post]
func CreateLogoutHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessTokenStr, _ := c.Cookie("access")

		_, claims, err := TokenFromCookie(accessTokenStr)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse access token"})
			slog.Error("failed to parse access token on logout", "err", err)
			return
		}

		userUUID, _ := uuid.Parse(claims.Subject)

		var refreshTokenDB models.RefreshTokens
		if db.First(&refreshTokenDB, "user_id = ?", userUUID).Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token not found, you need to login first"})
			return
		}

		c.SetSameSite(http.SameSiteLaxMode)

		if db.Delete(&refreshTokenDB).Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
			slog.Error("failed to logout", "err", err)
		}

		c.SetCookie("access", "", -1, "/", "", true, true)
		c.SetCookie("refresh", "", -1, "/", "", true, true)
		c.JSON(200, gin.H{"message": "logout successfully"})
	}
}
