package models

import (
	"github.com/google/uuid"
)

// User represents application user model
// @Description User account information
type User struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;"`
}

type RefreshTokens struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey;"`
	UserID       uuid.UUID `gorm:"type:uuid;not null;index"`
	RefreshToken string    `gorm:"type:varchar(512);not null"`
	IsRevoked    bool      `gorm:"default:false;not null"`
	User         User      `gorm:"foreignKey:UserID;references:ID"`
}
