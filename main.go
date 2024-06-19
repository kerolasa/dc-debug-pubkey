// Package main defines the dc-debug-pubkey executable entry point.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Template struct {
	SyncPubKeyDomain string `json:"syncPubKeyDomain"`
}

type PostData struct {
	Domain string `json:"domain"`
	Sig    string `json:"sig"`
	Hash   string `json:"hash"`
}

/*
 * The Domain Connect Debug Public Key is provided for Service Providers to
 * test syncPubKeyDomain setup. See also:
 * https://github.com/Domain-Connect/spec/blob/master/Domain%20Connect%20Spec%20Draft.adoc#digitally-sign-requests
 * https://exampleservice.domainconnect.org/sig
 */

func main() {
	// Init zerolog
	if isatty.IsTerminal(os.Stderr.Fd()) {
		log.Logger = log.Output(
			zerolog.ConsoleWriter{
				Out:        os.Stderr,
				TimeFormat: time.RFC3339,
			},
		)
	}
	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		return file + ":" + strconv.Itoa(line)
	}
	log.Logger = log.With().Caller().Logger()

	// Command line options
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s ./service-provider.template.json ./private_key.pem raw-POST-data\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s --postdata ./data.json ./service-provider.template.json\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "See also https://exampleservice.domainconnect.org/sig\n")
	}
	loglevel := flag.String("loglevel", "info", "loglevel can be one of: panic fatal error warn info debug trace")
	sigHost := flag.String("key", "", "host prefix in syncPubKeyDomain, when empty the domain is queried")
	postData := flag.String("postdata", "", "path to POST data json (omits need to have private key)")
	flag.Parse()
	level, err := zerolog.ParseLevel(*loglevel)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid loglevel")
	}
	zerolog.SetGlobalLevel(level)

	if flag.NArg() < 1 {
		log.Fatal().Msg("service provider template not defined, please see --help outout for usage")
	}
	template := getTemplate(flag.Arg(0))
	toBeVerified := PostData{
		Domain: versionedHostName(template, *sigHost),
	}

	if *postData == "" {
		if n := flag.NArg(); n != 3 {
			log.Fatal().Int("arguments", n).Msg("invalid number of arguments, please see --help outout for usage")
		}

		// Get input data
		privateKey := getPrivateKey(flag.Arg(1))

		// Sign payload
		toBeVerified.Hash = flag.Arg(2)
		signPayload(privateKey, &toBeVerified)
	} else {
		postBytes, err := os.ReadFile(*postData)
		if err != nil {
			log.Fatal().Err(err).Str("path", *postData).Msg("could not read file")
		}
		err = json.Unmarshal(postBytes, &toBeVerified)
		if err != nil {
			log.Fatal().Err(err).Str("path", *postData).Msg("could not unmarshal json")
		}
	}

	// Get public key
	publicKey := getPublicKey(toBeVerified.Domain)

	// Verify
	checkSignature(publicKey, toBeVerified)

	// Print POST data that would be sent DNS Provider
	marshaled, err := json.Marshal(toBeVerified)
	if err != nil {
		log.Warn().Err(err).Msg("could not marshal json")
	}
	var out bytes.Buffer
	err = json.Indent(&out, marshaled, "", "    ")
	if err != nil {
		log.Warn().Err(err).Msg("could not indent json")
	}
	fmt.Println(string(out.Bytes()))
}

func getPrivateKey(pathToKey string) any {
	log.Debug().Msg("read private key")
	keyBytes, err := os.ReadFile(pathToKey)
	if err != nil {
		log.Fatal().Err(err).Str("path", pathToKey).Msg("could not read file")
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		log.Fatal().Err(err).Str("path", pathToKey).Msg("could not decode private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		log.Fatal().Err(err).Str("path", pathToKey).Msg("could not parse private key")
	}
	return key
}

func getTemplate(pathToTemplate string) Template {
	log.Debug().Msg("read service provider template")
	var template Template
	templateBytes, err := os.ReadFile(pathToTemplate)
	if err != nil {
		log.Fatal().Err(err).Msg("could not read file")
	}
	err = json.Unmarshal(templateBytes, &template)
	if err != nil {
		log.Fatal().Err(err).Str("path", pathToTemplate).Msg("could not unmarshal json")
	}
	return template
}

func signPayload(key any, toBeVerified *PostData) {
	log.Debug().Msg("signing payload")
	msgHash := sha256.New()
	_, err := msgHash.Write([]byte(toBeVerified.Hash))
	if err != nil {
		log.Fatal().Err(err).Msg("could not hash post data")
	}
	hashSum := msgHash.Sum(nil)
	var signature []byte
	if privateKey, ok := key.(*rsa.PrivateKey); ok {
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashSum)
		if err != nil {
			log.Fatal().Err(err).Msg("could not sign post data")
		}
	} else {
		log.Fatal().Msg("private key is not a rsa key")
	}
	toBeVerified.Sig = base64.StdEncoding.EncodeToString(signature)
}

type txtRecord struct {
	p int
	d string
}

func versionedHostName(template Template, host string) string {
	dnsName := template.SyncPubKeyDomain
	if host != "" {
		dnsName = host + "." + template.SyncPubKeyDomain
	}
	return dnsName
}

func getPublicKey(dnsName string) rsa.PublicKey {
	log.Debug().Msg("reading public key from DNS")
	txt, err := net.LookupTXT(dnsName)
	if err != nil {
		log.Fatal().Err(err).Str("domain", dnsName).Msg("public key txt lookup failed")
	}

	var allRecords []txtRecord
	for _, r := range txt {
		var record txtRecord

		log.Debug().Str("txt", r).Msg("process txt record")
		fields := strings.Split(r, ",")
		for _, item := range fields {
			switch item[0] {
			case 'p':
				record.p, err = strconv.Atoi(item[2:])
				if err != nil {
					log.Fatal().Err(err).Str("item", item[2:]).Msg("invalid number in txt record")
				}
			case 'a':
				if item[2:] != "RS256" {
					log.Fatal().Str("algorithm", item[2:]).Msg("unexpected algorithm in txt record")
				}
			case 't':
				if item[2:] != "x509" {
					log.Fatal().Str("keytoken", item[2:]).Msg("unexpected key token in txt record")
				}
			case 'd':
				record.d = item[2:]
			default:
				log.Warn().Str("item", item).Msg("unexpected data in txt record")
			}
		}
		allRecords = append(allRecords, record)
	}

	// DNS can and will provide records in random order, sort them
	sort.Slice(allRecords, func(i, j int) bool { return allRecords[i].p < allRecords[j].p })

	// Convert the text record to pem format
	var pubkeyBase64 string
	pubkeyBase64 = "-----BEGIN PUBLIC KEY-----\n"
	for i := range allRecords {
		pubkeyBase64 += allRecords[i].d
	}
	pubkeyBase64 += "\n-----END PUBLIC KEY-----\n"

	// Extract certificate
	block, _ := pem.Decode([]byte(pubkeyBase64))
	if block == nil {
		log.Fatal().Str("domain", dnsName).Msg("public key pem decode failed")
	}
	x509parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal().Err(err).Str("domain", dnsName).Msg("public key x509 decode failed")
	}
	if x509parsed.(*rsa.PublicKey) == nil {
		log.Fatal().Str("domain", dnsName).Msg("public key does not have rsa key")
	}

	return *x509parsed.(*rsa.PublicKey)
}

func checkSignature(publicKey rsa.PublicKey, toBeVerified PostData) {
	log.Debug().Msg("checking signature")
	binarySig, err := base64.StdEncoding.DecodeString(toBeVerified.Sig)
	if err != nil {
		log.Fatal().Err(err).Msg("could not base64 decode")
	}
	hashed := sha256.Sum256([]byte(toBeVerified.Hash))
	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashed[:], binarySig)
	if err != nil {
		log.Error().Err(err).Msg("verify public key failed")
	}
}
