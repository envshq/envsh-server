package auth

import (
	"context"
	"fmt"

	"github.com/resend/resend-go/v3"
)

// ResendEmailSender sends verification codes via the Resend API.
type ResendEmailSender struct {
	client *resend.Client
	from   string
}

// NewResendEmailSender creates a new Resend-backed email sender.
func NewResendEmailSender(apiKey, from string) *ResendEmailSender {
	return &ResendEmailSender{
		client: resend.NewClient(apiKey),
		from:   from,
	}
}

// SendCode sends a verification code email via Resend.
func (s *ResendEmailSender) SendCode(_ context.Context, email, code string) error {
	_, err := s.client.Emails.Send(&resend.SendEmailRequest{
		From:    s.from,
		To:      []string{email},
		Subject: "Your envsh verification code",
		Text:    fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 5 minutes.", code),
	})
	if err != nil {
		return fmt.Errorf("sending email via resend: %w", err)
	}
	return nil
}
