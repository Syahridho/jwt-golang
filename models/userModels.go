package models

import (
	"time"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email                string `gorm:"unique"`
	Password             string
	ResetPasswordToken   string    `gorm:"index"`
	ResetPasswordExpiry  time.Time
}