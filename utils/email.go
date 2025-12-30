package utils

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
)

type EmailService struct {
	SMTPHost string
	SMTPPort string
	From     string
	Password string
}

func NewEmailService() *EmailService {
	return &EmailService{
		SMTPHost: os.Getenv("MAIL_HOST"),
		SMTPPort: os.Getenv("MAIL_PORT"),
		From:     os.Getenv("MAIL_USERNAME"),
		Password: os.Getenv("MAIL_PASSWORD"),
	}
}

func (e *EmailService) SendResetPasswordEmail(to, resetToken string) error {
	// URL reset password - sesuaikan dengan frontend Anda
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", os.Getenv("FRONTEND_URL"), resetToken)
	
	subject := "Reset Password Request"
	body := fmt.Sprintf(`
		<html>
		<body style="font-family: Arial, sans-serif; padding: 20px;">
			<h2 style="color: #333;">Reset Password</h2>
			<p>Anda menerima email ini karena ada permintaan untuk mereset password akun Anda.</p>
			<p>Klik link berikut untuk mereset password:</p>
			<p><a href="%s" style="background-color: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a></p>
			<p>Atau copy link berikut ke browser Anda:</p>
			<p style="background-color: #f5f5f5; padding: 10px; border-radius: 5px; word-break: break-all;">%s</p>
			<p><strong>Link ini akan kadaluarsa dalam 1 jam.</strong></p>
			<p>Jika Anda tidak merasa melakukan permintaan ini, abaikan email ini.</p>
			<hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
			<p style="color: #666; font-size: 12px;">Email ini dikirim secara otomatis, mohon tidak membalas email ini.</p>
		</body>
		</html>
	`, resetURL, resetURL)

	// Prepare message
	message := []byte(fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-version: 1.0;\r\n"+
			"Content-Type: text/html; charset=\"UTF-8\";\r\n"+
			"\r\n"+
			"%s\r\n",
		e.From, to, subject, body,
	))

	// Setup authentication
	auth := smtp.PlainAuth("", e.From, e.Password, e.SMTPHost)


	// Gmail menggunakan port 587 dengan STARTTLS atau port 465 dengan SSL
	if e.SMTPPort == "465" {
		// Untuk port 465 (SSL/TLS)
		return e.sendMailTLS(to, message)
	} else {
		// Untuk port 587 (STARTTLS)
		addr := fmt.Sprintf("%s:%s", e.SMTPHost, e.SMTPPort)
		err := smtp.SendMail(addr, auth, e.From, []string{to}, message)
		if err != nil {
			return fmt.Errorf("failed to send email: %v", err)
		}
	}

	return nil
}

// sendMailTLS sends email using TLS (for port 465)
func (e *EmailService) sendMailTLS(to string, message []byte) error {
	addr := fmt.Sprintf("%s:%s", e.SMTPHost, e.SMTPPort)

	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         e.SMTPHost,
	}

	// Connect to SMTP server with TLS
	conn, err := tls.Dial("tcp", addr, tlsconfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, e.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}
	defer client.Quit()

	// Authenticate
	auth := smtp.PlainAuth("", e.From, e.Password, e.SMTPHost)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("failed to authenticate: %v", err)
	}

	// Set sender
	if err = client.Mail(e.From); err != nil {
		return fmt.Errorf("failed to set sender: %v", err)
	}

	// Set recipient
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %v", err)
	}

	// Send message
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %v", err)
	}

	_, err = w.Write(message)
	if err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close writer: %v", err)
	}

	return nil
}
