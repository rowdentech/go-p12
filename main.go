package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"golang.org/x/crypto/ssh/terminal"
	"software.sslmate.com/src/go-pkcs12"
)

type arrayFlag []string

func (i *arrayFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}
func (i *arrayFlag) String() string {
	return strings.Join(*i, ", ")
}

var caPaths arrayFlag

func main() {

	certPathPtr := flag.String("cert", "", "Path to the primary certificate")
	keyPathPtr := flag.String("key", "", "Path to the private key for the primary certificate")
	flag.Var(&caPaths, "ca", "Path to a CA certificate to append to the p12 (can be passed multiple times)")

	flag.Parse()

	p12Path := flag.Arg(0)
	if p12Path == "" {
		log.Fatalf("Please set the desired p12 output path as the first argument")
	}

	x509Cert, err := decodeCertificate(*certPathPtr)
	if err != nil {
		log.Fatalf("failed to decode certificate: " + err.Error())
	}
	x509Key, err := decodePrivateKey(*keyPathPtr)
	if err != nil {
		log.Fatalf("failed to decode private key: " + err.Error())
	}

	x509CAs := []*x509.Certificate{}

	for _, path := range caPaths {
		cert, err := decodeCertificate(path)
		if err != nil {
			log.Fatalf("failed to decode CA certificate: " + err.Error())
		}
		x509CAs = append(x509CAs, cert)
	}

	fmt.Printf("Please enter the new password for the P12 file: ")
	password, _ := terminal.ReadPassword(int(os.Stdin.Fd()))

	pfxData, err := pkcs12.Encode(rand.Reader, x509Key, x509Cert, x509CAs, string(password))
	if err != nil {
		log.Fatalf("failed to encode p12 data: " + err.Error())
	}

	err = ioutil.WriteFile(p12Path, pfxData, 0644)
}

func decodePrivateKey(path string) (crypto.PrivateKey, error) {

	keyBytes, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	keyPem, _ := pem.Decode(keyBytes)
	if keyPem == nil {
		return nil, fmt.Errorf("Failed to parse key PEM data")
	}

	key, err := decryptKeyBytes(keyPem)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func decryptKeyBytes(key *pem.Block) (crypto.PrivateKey, error) {

	if key.Type == "RSA PRIVATE KEY" {
		fmt.Printf("Please enter the existing password for the private key: ")
		password, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println("")

		decryptedBytes, err := x509.DecryptPEMBlock(key, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}

		key.Bytes = decryptedBytes

		return x509.ParsePKCS1PrivateKey(key.Bytes)
	}

	return nil, fmt.Errorf("Unknown key type: " + key.Type)
}

func decodeCertificate(path string) (*x509.Certificate, error) {

	certBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	certPem, _ := pem.Decode(certBytes)
	if certPem == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM data")
	}

	x509Cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate body: %w", err)
	}

	return x509Cert, nil
}
