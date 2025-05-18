package middlewares

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"log/slog"
)

func CreateAuthMiddleware(db *gorm.DB) gin.HandlerFunc {

	return func(c *gin.Context) {
		accessToken, err := c.Cookie("access")
		slog.Debug(accessToken)
		if err != nil {
			c.JSON(401, gin.H{
				"message": "access cookie not found",
			})
			c.Abort()
		}

		c.Next()
	}
}
