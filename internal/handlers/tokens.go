package handlers

import (
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"log/slog"
	"medods_test_task/models"
	"net/http"
	"os"
	"time"
)

type MyClaims struct {
	Ip        string `json:"ip"`
	USERAGENT string `json:"useragent"`
	jwt.RegisteredClaims
}

type TokenMaker interface {
	CreateToken(tokenUUID string, userID string, ip string, USERAGENT string, duration time.Duration) (string, error)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type JWTMaker struct {
	SecretKey string
}

func (maker *JWTMaker) CreateToken(tokenUUID string, userID string, ip string, USERAGENT string, duration time.Duration) (string, error) {

	claims := &MyClaims{
		Ip:        ip,
		USERAGENT: USERAGENT,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			ID:        tokenUUID,
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

		tokenUUID := uuid.NewString()
		accessToken, err := tokenMaker.CreateToken(tokenUUID, uuidUserID.String(), c.ClientIP(), c.Request.UserAgent(), 15*time.Minute)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access token"})
			return
		}

		refreshToken := createRefreshToken(accessToken, tokenUUID)
		slog.Debug("refreshToken created", "token", refreshToken)
		encoded := base64.URLEncoding.EncodeToString([]byte(refreshToken))

		if err != nil {
			slog.Error("Failed to hash refresh token", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
			return
		}

		refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
		slog.Debug("refreshToken hash created", "token hash", refreshTokenHash)
		if err != nil {
			slog.Error("Failed to hash refresh token", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
		}

		tokens := models.RefreshTokens{
			ID:           uuid.New(),
			RefreshToken: string(refreshTokenHash),
			UserID:       user.ID,
		}

		c.SetCookie("access", accessToken, 15*60, "/", "", true, true)
		c.SetCookie("refresh", encoded, 3600*60, "/", "", true, true)
		c.SetSameSite(http.SameSiteLaxMode)

		if err := db.Create(&tokens).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
			return
		}

		// Формируем ответ
		response := TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: encoded,
		}

		c.JSON(http.StatusOK, response)
	}
}

func CreateRefreshTokensHandler(db *gorm.DB, tokenMaker TokenMaker) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessTokenStr, err := c.Cookie("access")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "No access token cookie"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch access token"})
				slog.Error("Failed to fetch access token", "err", err)
			}
			return
		}

		refreshTokenStr, err := c.Cookie("refresh")

		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token cookie"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch refresh token"})
				slog.Error("Failed to fetch refresh token", "err", err)
			}
			return
		}
		//get access and refresh token

		//validate them
		_, accessClaims, err := TokenFromCookie(accessTokenStr)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse access token"})
			slog.Error("Failed to parse access token", "err", err)
			return
		}

		if accessClaims.USERAGENT != c.Request.UserAgent() {
			c.SetCookie("access", "", -1, "/", "", true, true)
			c.SetCookie("refresh", "", -1, "/", "", true, true)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User agent invalidated"})
			return
		}

		tx := db.Begin()
		var refreshTokenDB models.RefreshTokens
		if err := tx.First(&refreshTokenDB, "user_id = ?", accessClaims.Subject).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "You need to auth on /tokens first"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
			}
			slog.Debug("refreshToken fetched from db", "user", accessClaims.Subject, "error", err)
			tx.Rollback()
			return
		}

		//if ok -> tx delete refresh token, refresh access and refreshTokenStr in cookies and database
		decoded, err := base64.URLEncoding.DecodeString(refreshTokenStr)
		slog.Debug("refreshToken decoded", "token", decoded)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to decode refresh token"})
			slog.Error("Failed decode refresh token", "err", err)
			tx.Rollback()
			return
		}
		slog.Debug("comparing started")
		err = bcrypt.CompareHashAndPassword([]byte(refreshTokenDB.RefreshToken), decoded)
		slog.Debug("comparing ended")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			c.SetCookie("access", "", -1, "/", "", true, true)
			c.SetCookie("refresh", "", -1, "/", "", true, true)
			tx.Rollback()
			slog.Debug("tokens are not the same")
			return
		}

		userID := accessClaims.Subject
		slog.Debug("user id from claims:", userID)
		slog.Debug("deleting token from db")

		userUUID, _ := uuid.Parse(userID)

		//var refreshTokenToDeleteDB = models.RefreshTokens{
		//	UserID: userUUID,
		//}

		if err = db.Where("user_id = ?", userUUID).Delete(&models.RefreshTokens{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process refresh operation"})
			slog.Error("Failed to delete refresh token", "err", err)
			tx.Rollback()
			return
		}
		slog.Debug("token deleted from db")

		tokenUUID := uuid.NewString()

		accessToken, err := tokenMaker.CreateToken(tokenUUID, userID, c.ClientIP(), c.Request.UserAgent(), 15*time.Minute)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access token"})
			tx.Rollback()
			return
		}

		newRefreshToken := createRefreshToken(accessToken, tokenUUID)
		encoded := base64.URLEncoding.EncodeToString([]byte(newRefreshToken))

		if err != nil {
			slog.Error("Failed to hash refresh token", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
			tx.Rollback()
			return
		}

		refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)

		if err != nil {
			slog.Error("Failed to hash refresh token", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create refresh token"})
			tx.Rollback()
			return
		}

		tokens := models.RefreshTokens{
			ID:           uuid.New(),
			RefreshToken: string(refreshTokenHash),
			UserID:       userUUID,
		}

		c.SetCookie("access", accessToken, 15*60, "/", "", true, true)
		c.SetCookie("refresh", encoded, 3600*60, "/", "", true, true)
		c.SetSameSite(http.SameSiteLaxMode)

		if err := db.Create(&tokens).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
			tx.Rollback()
			return
		}

		// Формируем ответ
		response := TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: encoded,
		}

		tx.Commit()
		c.JSON(http.StatusOK, response)

	}
}

func CreateLogoutHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		//already validated in middleware
		accessTokenStr, _ := c.Cookie("access")

		_, claims, err := TokenFromCookie(accessTokenStr)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch access token"})
			return
		}

		userUUID, _ := uuid.Parse(claims.Subject)

		var refreshTokenDB models.RefreshTokens

		if db.First(&refreshTokenDB, "user_id = ?", userUUID).Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token found"})
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

func TokenFromCookie(tokenStr string) (*jwt.Token, *MyClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &MyClaims{}, func(token *jwt.Token) (interface{}, error) {
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))

	if err != nil {
		return nil, nil, err
	}

	claims, ok := token.Claims.(*MyClaims)

	if !ok {
		return nil, nil, errors.New("cant't parse claims to myclaims")
	}

	return token, claims, nil
}

func createRefreshToken(accessTokenStr string, uuid string) string {
	runes := []rune(accessTokenStr)
	first10 := string(runes[:10])
	token := first10 + uuid

	return token
}
