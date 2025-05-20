package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

type IPChangeRequest struct {
	UserUUID string `json:"userUUID"`
	OldIP    string `json:"oldIP"`
	NewIP    string `json:"newIP"`
}
type MyClaims struct {
	Ip        string `json:"ip"`
	USERAGENT string `json:"useragent"`
	jwt.RegisteredClaims
}

type TokenMaker interface {
	CreateToken(tokenUUID string, userID string, ip string, USERAGENT string, duration time.Duration) (string, error)
}

// TokenResponse represents successful token generation response
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

// @Summary Get new access and refresh tokens
// @Description Generates new JWT access token and refresh token for authenticated user. Requires valid user ID.
// @Tags Auth
// @Accept json
// @Produce json
// @Param user_id path string true "User UUID"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} map[string]string "error: Invalid user ID format"
// @Failure 404 {object} map[string]string "error: User not found / tokens already exists"
// @Failure 500 {object} map[string]string "error: Failed to create tokens/session"
// @Router /tokens/{user_id} [get]
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

// @Summary Refresh authentication tokens
// @Description Refreshes access and refresh tokens using valid refresh token. Invalidates old tokens and issues new ones.
// @Tags Auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} TokenResponse
// @Failure 400 {object} map[string]string "error: Failed to decode refresh token"
// @Failure 401 {object} map[string]string "error: No access/refresh token cookie | User agent invalidated | Invalid refresh token"
// @Failure 404 {object} map[string]string "error: You need to auth on /tokens first"
// @Failure 500 {object} map[string]string "error: Failed to fetch/parse tokens | Failed to create tokens/session"
// @Router /refresh [post]
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

		userID := accessClaims.Subject
		userUUID, _ := uuid.Parse(userID)
		slog.Debug("user id from claims:", userID)

		if accessClaims.USERAGENT != c.Request.UserAgent() {
			c.SetCookie("access", "", -1, "/", "", true, true)
			c.SetCookie("refresh", "", -1, "/", "", true, true)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User agent invalidated"})
			return
		}

		if accessClaims.Ip != c.ClientIP() {
			notificationData := IPChangeRequest{
				UserUUID: userID,
				OldIP:    accessClaims.Ip,
				NewIP:    c.ClientIP(),
			}

			jsonData, _ := json.Marshal(notificationData)

			_, err = http.Post(os.Getenv("Webhook"), "application/json", bytes.NewBuffer(jsonData))

			if err != nil {
				slog.Error("Failed to notify about new ip address", "err", err, "ip", c.ClientIP(), "old ip", accessClaims.Ip)
			}
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

		slog.Debug("deleting token from db")

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
