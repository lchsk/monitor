package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/smtp"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/lchsk/scheduler"
)

type Config struct {
	Account  Account  `toml:"account"`
	Alert    Alert    `toml:"alert"`
	SSLCheck SSLCheck `toml:"ssl_check"`
}

type Alert struct {
	Email string `toml:"email"`
}

type SSLCheck struct {
	Hosts             []string `toml:hosts`
	DaysBeforeWarning int      `toml:"days_before_warning"`
}

type Account struct {
	Server   string `toml:"server"`
	Port     int    `toml:"port"`
	Email    string `toml:"email"`
	Password string `toml:"password"`
}

type Email struct {
	To      string
	Subject string
	Body    string
}

func SendEmail(sender Account, email Email) {
	auth := smtp.PlainAuth("", sender.Email, sender.Password, sender.Server)
	to := []string{email.To}

	body := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", email.To, email.Subject, email.Body)

	err := smtp.SendMail(fmt.Sprintf("%s:%d", sender.Server, sender.Port), auth, sender.Email, to, []byte(body))
	if err != nil {
		log.Fatal("fail: ", err)
	} else {
		fmt.Println("Email sent")
	}
}

func CheckSSL(conf *Config) {
	for _, host := range conf.SSLCheck.Hosts {
		fmt.Printf("Checking SSL for %s\n", host)

		conn2, _ := tls.Dial("tcp", host, &tls.Config{})

		now := time.Now()

		for _, chain := range conn2.ConnectionState().VerifiedChains {
			for _, cert := range chain {
				if now.AddDate(0, 0, conf.SSLCheck.DaysBeforeWarning).After(cert.NotAfter) {
					fmt.Printf("=== SSL expires soon, expires: %v ===\n", cert.NotAfter)

					email := Email{
						To:      conf.Alert.Email,
						Subject: fmt.Sprintf("SSL Certificate for %s expires soon - %v", host, cert.NotAfter),
						Body:    "",
					}

					SendEmail(conf.Account, email)
				} else {
					fmt.Printf("SSL ok, expires: %v\n", cert.NotAfter)
				}
			}
		}
	}
}

func main() {
	flagTestEmail := flag.Bool("test-email", false, "Send test email")
	flagCheckSSL := flag.Bool("check-ssl", false, "Run SSL check")
	flag.Parse()

	configPath := filepath.Join("./monitor.toml")

	f, err1 := ioutil.ReadFile(configPath)

	if err1 != nil {
		log.Fatal("Can't read: ", err1)
	}

	conf := &Config{}

	if _, err := toml.Decode(string(f), conf); err != nil {
		log.Fatal("Failed to read the config file! ", err)
	}

	if *flagTestEmail {
		email := Email{
			To:      conf.Alert.Email,
			Subject: "Monitor Test",
			Body:    "Test",
		}

		SendEmail(conf.Account, email)
	}

	if *flagCheckSSL {
		CheckSSL(conf)
	}

	mgr := scheduler.Scheduler{}
	mgr.Schedule(24*time.Hour, func() {
		fmt.Printf("Now: %v\n", time.Now())
		CheckSSL(conf)
	})

	mgr.Wait()
}
