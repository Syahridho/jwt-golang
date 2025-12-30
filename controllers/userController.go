package controllers

import (
	"jwt-gin-gorm/initializers"
	"jwt-gin-gorm/models"
	"jwt-gin-gorm/utils"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	// get the email/password off req body
	var body struct {
		Email string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return 
	}

	// hash password 
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
	}

	// create the user
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})

		return 
	}

	// respond
	c.JSON(http.StatusOK, gin.H{})

}

func Login(c *gin.Context) {
	// get email and pass off req body
	var body struct {
		Email string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to red body",
		})

		return
	}

	// look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})

		return
	}

	// compare send in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})

		return
	}

	// generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})
	
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	 
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to create token",
		})

		return
	}

	// send it back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600 * 24 * 30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})

}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")


	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func ForgotPassword(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Email tidak valid",
		})
		return
	}

	// Cari user berdasarkan email
	var user models.User
	result := initializers.DB.First(&user, "email = ?", body.Email)

	if result.Error != nil {
		// Untuk keamanan, jangan beritahu user bahwa email tidak ditemukan
		c.JSON(http.StatusOK, gin.H{
			"message": "Jika email terdaftar, link reset password telah dikirim",
		})
		return
	}

	// Generate reset token
	resetToken, err := utils.GenerateRandomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Gagal membuat token reset",
		})
		return
	}

	// Hash token sebelum disimpan di database
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(resetToken), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Gagal membuat token reset",
		})
		return
	}

	// Update user dengan reset token dan expiry (1 jam dari sekarang)
	user.ResetPasswordToken = string(hashedToken)
	user.ResetPasswordExpiry = time.Now().Add(time.Hour * 1)
	initializers.DB.Save(&user)

	// Kirim email dengan logging detail
	emailService := utils.NewEmailService()
	
	err = emailService.SendResetPasswordEmail(user.Email, resetToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Gagal mengirim email: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Jika email terdaftar, link reset password telah dikirim",
	})
}

func ResetPassword(c *gin.Context) {
	var body struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Data tidak valid",
		})
		return
	}

	// Cari user dengan token yang masih valid
	var users []models.User
	initializers.DB.Where("reset_password_expiry > ?", time.Now()).Find(&users)

	var validUser *models.User
	for _, user := range users {
		// Verifikasi token
		err := bcrypt.CompareHashAndPassword([]byte(user.ResetPasswordToken), []byte(body.Token))
		if err == nil {
			validUser = &user
			break
		}
	}

	if validUser == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Token tidak valid atau sudah kadaluarsa",
		})
		return
	}

	// Hash password baru
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Gagal mengubah password",
		})
		return
	}

	// Update password dan hapus reset token
	validUser.Password = string(hashedPassword)
	validUser.ResetPasswordToken = ""
	validUser.ResetPasswordExpiry = time.Time{}
	initializers.DB.Save(validUser)

	c.JSON(http.StatusOK, gin.H{
		"message": "Password berhasil diubah",
	})
}