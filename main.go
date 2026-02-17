// Package main defines the dc-debug-pubkey executable entry point.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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

type AlgType uint8

const (
	RS256 AlgType = iota // RSA Signature (the default)
	RS384
	RS512
	PS256 // Probabilistic Signature Scheme
	PS384
	PS512
	ES256 // Elliptic Curve Digital Signature
	ES384
	ES512
	Ed25519 // Edwards-curve Digital Signature
	Ed448
)

func (a AlgType) Name() string {
	switch a {
	case RS256:
		return "RS256"
	case RS384:
		return "RS384"
	case RS512:
		return "RS512"
	case PS256:
		return "PS256"
	case PS384:
		return "PS384"
	case PS512:
		return "PS512"
	case ES256:
		return "ES256"
	case ES384:
		return "ES384"
	case ES512:
		return "ES512"
	case Ed25519:
		return "Ed25519"
	case Ed448:
		return "Ed448"
	}
	return "unknown"
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
		fmt.Fprintf(os.Stderr, "Usage: %s ./example.template.json ./example.private-key.pem 'VTxLc7lHPIJ2HnTVI0UvlCY8dTeomjujk6I9H2T6rupu8toH045SvnuPIY89yXd'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s --loglevel debug --postdata ./example.post.json ./example.template.json\n", os.Args[0])
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

	// Domain Connect spec: The digital signature will be generated on
	// the full query string only, excluding the sig and key parameters.
	// This is everything after the ?, except the sig and key values.
	toBeVerified.Hash = removeSigAndKey(toBeVerified.Hash)

	// Get public key
	publicKeys := getPublicKey(toBeVerified.Domain)

	// Verify
	checkSignature(publicKeys, toBeVerified)

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
	fmt.Println(out.String())
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
		panic("fatal did not terminate") // staticcheck SA5011 goaround
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

func removeSigAndKey(input string) string {
	queryParameters := strings.Split(input, "&")
	newParameters := ""
	for _, parameter := range queryParameters {
		kv := strings.Split(parameter, "=")
		switch kv[0] {
		case "key", "sig":
			log.Debug().Str("parameter", kv[0]).Msg("query string parameter removed")
			continue
		default:
			amp := "&"
			if newParameters == "" {
				amp = ""
			}
			if len(kv) > 1 {
				newParameters = newParameters + amp + kv[0] + "=" + kv[1]
			} else {
				newParameters = newParameters + amp + kv[0]
			}
		}
	}
	return newParameters
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

func getAlg(alg string) AlgType {
	switch alg {
	case "RS256":
		return RS256
	case "RS384":
		return RS384
	case "RS512":
		return RS512
	case "PS256":
		return PS256
	case "PS384":
		return PS384
	case "PS512":
		return PS512
	case "ES256":
		return ES256
	case "ES384":
		return ES384
	case "ES512":
		return ES512
	case "Ed25519":
		return Ed25519
	case "Ed448":
		return Ed448
	default:
		log.Fatal().Str("algorithm", alg).Msg("unexpected algorithm in txt record")
	}
	return RS256
}

func getPublicKey(dnsName string) map[AlgType][]byte {
	txtLog := log.With().Str("record", dnsName).Logger()
	txtLog.Debug().Msg("reading public key from DNS")
	txt, err := net.LookupTXT(dnsName)
	if err != nil {
		txtLog.Fatal().Err(err).Msg("public key txt lookup failed")
	}

	allRecords := make(map[AlgType][]txtRecord)
	for _, r := range txt {
		var record txtRecord

		txtLog.Debug().Str("txt", r).Msg("process txt record")
		fields := strings.Split(r, ",")
		var alg AlgType
		for _, item := range fields {
			switch item[0] {
			case 'p':
				record.p, err = strconv.Atoi(item[2:])
				if err != nil {
					txtLog.Fatal().Err(err).Str("item", item[2:]).Msg("invalid number in txt record")
				}
			case 'a':
				alg = getAlg(item[2:])
			case 't':
				if item[2:] != "x509" {
					txtLog.Fatal().Str("keytoken", item[2:]).Msg("unexpected key token in txt record")
				}
			case 'd':
				record.d = item[2:]
			default:
				txtLog.Warn().Str("item", item).Msg("unexpected data in txt record")
			}
		}
		list := allRecords[alg]
		list = append(list, record)
		allRecords[alg] = list
	}

	// The return value
	keyMap := make(map[AlgType][]byte)

	for alg, list := range allRecords {
		// DNS can and will provide records in random order, sort them
		sort.Slice(list, func(i, j int) bool {
			return list[i].p < list[j].p
		})

		// Convert the text record to pem format
		var pubkeyBase64 string
		pubkeyBase64 = "-----BEGIN PUBLIC KEY-----\n"
		for i := range list {
			pubkeyBase64 += list[i].d
		}
		pubkeyBase64 += "\n-----END PUBLIC KEY-----\n"

		// Extract certificate
		block, _ := pem.Decode([]byte(pubkeyBase64))
		if block == nil {
			txtLog.Fatal().Msg("public key pem decode failed")
			panic("fatal did not terminate") // staticcheck SA5011 goaround
		}
		keyMap[alg] = block.Bytes
	}

	return keyMap
}

func checkSignature(publicKeys map[AlgType][]byte, toBeVerified PostData) {
	log.Debug().Msg("checking signature")
	binarySig, err := base64.StdEncoding.DecodeString(toBeVerified.Sig)
	if err != nil {
		log.Fatal().Err(err).Msg("could not base64 decode")
	}
	hashed := sha256.Sum256([]byte(toBeVerified.Hash))

	verifyOK := false

	for alg, publicKey := range publicKeys {
		algLog := log.With().Str("alg", alg.Name()).Logger()

		x509parsed, err := x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			algLog.Fatal().Err(err).Msg("public key x509 decode failed")
		}

		hash := crypto.SHA256
		switch alg {
		case RS384, PS384, ES384:
			hash = crypto.SHA384
		case RS512, PS512, ES512:
			hash = crypto.SHA512
		}

		switch alg {
		case RS256, RS384, RS512:
			if x509parsed.(*rsa.PublicKey) == nil {
				algLog.Fatal().Msg("public key does not have key")
				continue
			}
			err = rsa.VerifyPKCS1v15(x509parsed.(*rsa.PublicKey), hash, hashed[:], binarySig)
			if err != nil {
				algLog.Error().Err(err).Msg("verify public key failed")
			} else {
				verifyOK = true
				algLog.Debug().Msg("verify ok")
				goto loopDone
			}

		case PS256, PS384, PS512:
			if x509parsed.(*rsa.PublicKey) == nil {
				algLog.Fatal().Msg("public key does not have key")
				continue
			}
			err = rsa.VerifyPSS(x509parsed.(*rsa.PublicKey), hash, hashed[:], binarySig, nil)
			if err != nil {
				algLog.Error().Err(err).Msg("verify public key failed")
			} else {
				verifyOK = true
				algLog.Debug().Msg("verify ok")
				goto loopDone
			}

		case ES256, ES384, ES512:
			if x509parsed.(*ecdsa.PublicKey) == nil {
				algLog.Fatal().Msg("public key does not have key")
			}
			ok := ecdsa.VerifyASN1(x509parsed.(*ecdsa.PublicKey), hashed[:], binarySig)
			if !ok {
				algLog.Error().Err(err).Msg("verify public key failed")
			} else {
				verifyOK = true
				algLog.Debug().Msg("verify ok")
				goto loopDone
			}

		case Ed25519, Ed448:
			if x509parsed.(*ed25519.PublicKey) == nil {
				algLog.Fatal().Msg("public key does not have key")
			}
			ok := ed25519.Verify(*x509parsed.(*ed25519.PublicKey), hashed[:], binarySig)
			if !ok {
				algLog.Error().Err(err).Msg("verify public key failed")
			} else {
				verifyOK = true
				algLog.Debug().Msg("verify ok")
				goto loopDone
			}

		default:
			algLog.Fatal().Msg("unexpected verification algorithm")
		}
	}

loopDone:

	if !verifyOK {
		log.Error().Msg("verification failed")
	}
}
