package main

import (
	"log"
	"net/smtp"
)

func main() {
	// Set up authentication information.
	smtp.Dial("smtp.gmail.com")
	auth := smtp.PlainAuth(
		"Kunal",
		"kunalht1@gmail.com",
		"mypassword",
		"smtp.gmail.com",
	)
	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	err := smtp.SendMail(
		"smtp.gmail.com:465",
		auth,
		"sender@example.org",
		[]string{"kunalht@hotmail.com"},
		[]byte("This is the email body."),
	)
	if err != nil {
		log.Fatal(err)
	}
}