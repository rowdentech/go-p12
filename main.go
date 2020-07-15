package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"golang.org/x/crypto/ssh/terminal"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {

	caPathPtr := flag.String("ca", "", "Path to the CA certificate")
	certPathPtr := flag.String("cert", "", "Path to the client certificate")
	keyPathPtr := flag.String("key", "", "Path to the private key for the client certificate")

	flag.Parse()

	p12Path := flag.Arg(0)
	if p12Path == "" {
		log.Fatalf("Please set the desired p12 output path as the first argument")
	}

	fmt.Println("ca:", *caPathPtr)
	fmt.Println("cert:", *certPathPtr)
	fmt.Println("key:", *keyPathPtr)

	caBytes, err := ioutil.ReadFile(*caPathPtr)
	if err != nil {
		log.Fatalf("failed to read CA file: " + err.Error())
	}

	caPem, _ := pem.Decode(caBytes)
	if caPem == nil {
		log.Fatalf("failed to parse CA PEM data")
	}

	x509CA, err := x509.ParseCertificate(caPem.Bytes)
	if err != nil {
		log.Fatalf("failed to parse CA certificate: " + err.Error())
	}

	x509Key, err := decodePrivateKey(*keyPathPtr)

	fmt.Printf("Please enter the new password for the P12 file: ")
		password, _ := terminal.ReadPassword(int(os.Stdin.Fd()))

	pfxData, err := pkcs12.Encode(rand.Reader, x509Key, x509CA, nil, string(password))
	if err != nil {
		log.Fatalf("failed to encode p12 data: " + err.Error())
	}

	err = ioutil.WriteFile(p12Path, pfxData, 0644)
}

func decodePrivateKey(path string) (crypto.PrivateKey, error) {

	keyBytes, err := ioutil.ReadFile(path)

	if err != nil {
		log.Fatalf("failed to read private key file:" + err.Error())
	}

	keyPem, _ := pem.Decode(keyBytes)
	if keyPem == nil {
		return nil, fmt.Errorf("Failed to parse key PEM data")
	}

	key, err := decodeKeyBytes(keyPem)
	if err != nil {
		log.Fatalf("failed to decode private key file:" + err.Error())
	}

	return key, nil
}

func decodeKeyBytes(key *pem.Block) (crypto.PrivateKey, error) {

	if key.Type == "RSA PRIVATE KEY" {
		fmt.Printf("Please enter the existing password for the private key: ")
		password, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println("")

		decryptedBytes, err := x509.DecryptPEMBlock(key, []byte(password))
		if err != nil {
			log.Fatalf("Could not decrypt private key: " + err.Error())
		}

		key.Bytes = decryptedBytes

		return x509.ParsePKCS1PrivateKey(key.Bytes)
	}

	return nil, fmt.Errorf("Unknown key type: " + key.Type)
}
