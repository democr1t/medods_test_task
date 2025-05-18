package models

import (
	"github.com/google/uuid"
)

// User модель с UUID в качестве первичного ключа
type User struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;"`
}

type RefreshTokens struct {
	UserID       uuid.UUID `gorm:"primaryKey;type:uuid;not null;index;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	RefreshToken string    `gorm:"type:varchar(512);not null"`
	IsRevoked    bool      `gorm:"default:false;not null"`
	User         User      `gorm:"foreignKey:UserID;references:ID"`
}
