package main

import (
	"jwt-gin-gorm/controllers"
	"jwt-gin-gorm/initializers"
	"jwt-gin-gorm/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	router := gin.Default()

  	router.POST("/signup", controllers.Signup)
  	router.POST("/login", controllers.Login)
  	router.GET("/validate", middleware.RequireAuth, controllers.Validate)
	router.POST("/forgot-password", controllers.ForgotPassword)
	router.POST("/reset-password", controllers.ResetPassword)

	router.Run()
}