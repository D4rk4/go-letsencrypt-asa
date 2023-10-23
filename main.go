package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

type ASAConfig struct {
	MgmtIP       string
	MgmtPort     string
	Username     string
	Password     string
	VPNInterface string
	Domain	     string
	Force 	     bool
}

func (asa *ASAConfig) serverURL() string {
	return fmt.Sprintf("https://%s:%s", asa.MgmtIP, asa.MgmtPort)
}

func (asa *ASAConfig) post(url string, data map[string]interface{}) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	jsonData, _ := json.Marshal(data)


	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "REST API Agent")
	req.SetBasicAuth(asa.Username, asa.Password)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making request: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 201 {
		fmt.Println("The certificate has been installed successfully.")
	} else if resp.StatusCode == 200 {
		fmt.Println("The certificate has been pinned to the interface.")
	} else {
		fmt.Println("Something went wrong.")
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Request URL: %s", url)
		log.Printf("Request JSON: %s", string(jsonData))
		log.Printf("Response Body: %s", string(body))
	}
}

func (asa *ASAConfig) InstallCertToASA(certPKCS12 []byte) {
	// Split the base64-encoded certificate data into lines
	certBase64 := base64.StdEncoding.EncodeToString(certPKCS12)
	lines := []string{"-----BEGIN PKCS12-----"}
	for len(certBase64) > 64 {
		lines = append(lines, certBase64[:64])
		certBase64 = certBase64[64:]
	}
	lines = append(lines, certBase64)
	lines = append(lines, "-----END PKCS12-----")

	// Install the certificate on ASA
	data := map[string]interface{}{
		"certPass": "automation",
		"kind":     "object#IdentityCertificate",
		"certText": lines,
		"name":     "ALE_"+time.Now().Format("20060102"),
	}
	asa.post(asa.serverURL()+"/api/certificate/identity", data)

	cmd := fmt.Sprintf("ssl trust-point %s %s", "ALE_"+time.Now().Format("20060102"), asa.VPNInterface)
	data = map[string]interface{}{
		"commands": []string{cmd, "write"},
	}
	asa.post(asa.serverURL()+"/api/cli", data)
}

func (u *MyUser) GetEmail() string {
	return u.Email
}

func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// Check of certificate will expire in less than 7 days
func shouldRenew(certPath string) bool {
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return true // If we can't read the certificate, better renew it
	}

	cert, err := certcrypto.ParsePEMCertificate(certData)
	if err != nil {
		return true // If we can't parse the certificate, better renew it
	}

	timeLeft := cert.NotAfter.Sub(time.Now())
	return timeLeft < (7 * 24 * time.Hour)
}

// Function to parse all certificates from the PEM data
func parseAllCertificates(certPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("failed to decode PEM block containing a certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		certPEM = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs, nil
}


func main() {
	// Load configuration
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Can't pares config: %s", err)
	}

	email := viper.GetString("acme.email")
	domain := viper.GetString("acme.domain")
	apiToken := viper.GetString("cloudflare.apiToken")
	cfEmail := viper.GetString("cloudflare.email")
	accountKeyPEM := viper.GetString("acme.accountKey")

	// Set environment variables for lego to use Cloudflare DNS
	os.Setenv("CLOUDFLARE_EMAIL", cfEmail)
	os.Setenv("CLOUDFLARE_DNS_API_TOKEN", apiToken)

	// Create ASA configuration
	asaConfig := &ASAConfig{
		MgmtIP:       viper.GetString("asa.mgmtip"),
		MgmtPort:     viper.GetString("asa.mgmtport"),
		Username:     viper.GetString("asa.username"),
		Password:     viper.GetString("asa.password"),
		VPNInterface: viper.GetString("asa.vpninterface"),
		Domain:       domain,
		Force:        viper.GetBool("asa.force"),
	}

	var privateKey crypto.PrivateKey
	var err error

	if accountKeyPEM == "" {
		privateKey, err = certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
		if err != nil {
			log.Fatalf("Can't generate private key: %s", err)
		}
		keyData := certcrypto.PEMBlock(privateKey)
		keyDataPEM := pem.EncodeToMemory(keyData) // Convert to PEM format
		viper.Set("acme.accountKey", string(keyDataPEM))
		if err := viper.WriteConfig(); err != nil {
			log.Fatalf("Can't write key to config: %s", err)
		}
	} else {
		privateKey, err = certcrypto.ParsePEMPrivateKey([]byte(accountKeyPEM))
		if err != nil {
			log.Fatalf("Can't extract key from config: %s", err)
		}
	}


	myUser := MyUser{
		Email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatalf("Can't create lego client: %s", err)
	}

	// Register user
	if myUser.Registration == nil { // ToDo: Fix it
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatalf("Error registering the user: %s", err)
		}
		myUser.Registration = reg
	}

	// Create DNS provider
	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		log.Fatalf("Error creating DNS provider: %s", err)
	}

	err = client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers([]string{"8.8.8.8:53"}))
	if err != nil {
		log.Fatalf("Error setting DNS provider: %s", err)
	}

	domainCertPath := domain + ".crt"
	if asaConfig.Force {
		// Forcefully install the certificate on ASA without obtaining a new one
		certPKCS12, err := ioutil.ReadFile(domain + ".p12")
		if err != nil {
			log.Fatalf("Error reading PKCS12 certificate: %s", err)
		}

		asaConfig.InstallCertToASA(certPKCS12)

		fmt.Println("Certificate installed on ASA!")
	} else if _, err := os.Stat(domainCertPath); os.IsNotExist(err) || shouldRenew(domainCertPath) {
		// If the certificate doesn't exist or is expiring in less than 7 days, obtain a new one

		// Request certificate
		request := certificate.ObtainRequest{
			Domains: []string{domain},
			Bundle:  true,
		}
		certificates, err := client.Certificate.Obtain(request)
		if err != nil {
			log.Fatalf("Error obtaining the certificate: %s", err)
		}

		// Save the certificate and key
		err = ioutil.WriteFile(domain+".crt", certificates.Certificate, 0644)
		if err != nil {
			log.Fatalf("Error saving the certificate: %s", err)
		}
		err = ioutil.WriteFile(domain+".key", certificates.PrivateKey, 0644)
		if err != nil {
			log.Fatalf("Error saving the key: %s", err)
		}

		// Convert the certificate and key to PKCS12 format
		certBytes, err := ioutil.ReadFile(domain + ".crt")
		if err != nil {
			log.Fatalf("Error reading the certificate file: %s", err)
		}
		
		keyBytes, err := ioutil.ReadFile(domain + ".key")
		if err != nil {
			log.Fatalf("Error reading the key file: %s", err)
		}
		
		// Parse all certificates
		certs, err := parseAllCertificates(certBytes)
		if err != nil {
			log.Fatalf("Error parsing the certificates: %s", err)
		}

		// Parse the private key
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			log.Fatalf("Failed to decode PEM block containing the private key")
		}

		var key interface{}
		if block.Type == "RSA PRIVATE KEY" {
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		} else if block.Type == "PRIVATE KEY" {
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		} else {
			log.Fatalf("Unsupported key type %s", block.Type)
		}

		if err != nil {
			log.Fatalf("Error parsing the private key: %s", err)
		}
		
		pkcs12Data, err := pkcs12.Encode(rand.Reader, key, certs[0], certs[1:], "automation")


		// Save the PKCS12 data to a file
		pkcs12FileName := domain + time.Now().Format("20060102") + ".p12"
		err = ioutil.WriteFile(pkcs12FileName, pkcs12Data, 0644)
		if err != nil {
			log.Fatalf("Error saving PKCS12 certificate: %s", err)
		}
		// Install the certificate on ASA
		certPKCS12, err := ioutil.ReadFile(domain + time.Now().Format("20060102") + ".p12")
		if err != nil {
			log.Fatalf("Error reading PKCS12 certificate: %s", err)
		}

		asaConfig.InstallCertToASA(certPKCS12)

		fmt.Println("Certificate successfully obtained and installed on ASA!")
	} else {
		fmt.Println("Certificate is still valid and doesn't require renewal.")
	}
}
