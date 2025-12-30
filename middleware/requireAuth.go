package middleware

import (
	"fmt"
	"jwt-gin-gorm/initializers"
	"jwt-gin-gorm/models"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(c *gin.Context) {
	// get the cookie off req
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	// decode/validate it
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {
		log.Fatal(err)
	}
	
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// check the exp
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// find the user with token sub
		var user models.User
		initializers.DB.First(&user ,claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// attact to req
		c.Set("user", user)
		
		// continue
		c.Next()
	} else {
		fmt.Println(err)
	}
} 