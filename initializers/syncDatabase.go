package initializers

import "jwt-gin-gorm/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}