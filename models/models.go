package models

import (
	"github.com/google/uuid"
	"time"
)

// User модель с UUID в качестве первичного ключа
type User struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;"`
}

type Session struct {
	RefreshToken  string    `gorm:"type:varchar(512);not null"`
	UserID        uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	LastUSERAGENT string    `gorm:"type:varchar(255);not null"`
	LastIP        string    `gorm:"type:varchar(255);not null"`
	IsRevoked     bool      `gorm:"default:false;not null"`
	CreatedAt     time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	ExpiresAt     time.Time `gorm:"type:timestamp;not null"`
	User          User      `gorm:"foreignKey:UserID;references:ID"`
}
