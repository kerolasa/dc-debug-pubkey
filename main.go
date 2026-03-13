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
	"crypto/sha512"
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

// sigScheme identifies the signature algorithm family.
type sigScheme int

const (
	schemeUnknown  sigScheme = iota
	schemeRSAPKCS1           // RS256, RS384, RS512
	schemeRSAPSS             // PS256, PS384, PS512
	schemeECDSA              // ES256, ES384, ES512
	schemeEd25519            // Ed25519
)

// cachedCert bundles a public key with the signature scheme and hash algorithm
// declared by the provider's DNS TXT record.
type cachedCert struct {
	key    crypto.PublicKey
	scheme sigScheme
	hash   crypto.Hash // not used for Ed25519
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
	cert := getPublicKey(toBeVerified.Domain)

	// Verify
	checkSignature(cert, toBeVerified)

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

// hashData returns the digest of data using the given hash algorithm.
// Supports crypto.SHA256, crypto.SHA384, and crypto.SHA512.
func hashData(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		return d[:]
	default:
		d := sha256.Sum256(data)
		return d[:]
	}
}

func signPayload(key any, toBeVerified *PostData) {
	log.Debug().Msg("signing payload")
	var (
		signature []byte
		err       error
	)
	switch k := key.(type) {
	case *rsa.PrivateKey:
		hashed := sha256.Sum256([]byte(toBeVerified.Hash))
		signature, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hashed[:])
		if err != nil {
			log.Fatal().Err(err).Msg("could not sign post data")
		}
	case *ecdsa.PrivateKey:
		hashed := sha256.Sum256([]byte(toBeVerified.Hash))
		signature, err = ecdsa.SignASN1(rand.Reader, k, hashed[:])
		if err != nil {
			log.Fatal().Err(err).Msg("could not sign post data")
		}
	case ed25519.PrivateKey:
		signature, err = k.Sign(rand.Reader, []byte(toBeVerified.Hash), crypto.Hash(0))
		if err != nil {
			log.Fatal().Err(err).Msg("could not sign post data")
		}
	default:
		log.Fatal().Msg("unsupported private key type")
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

func getPublicKey(dnsName string) cachedCert {
	txtLog := log.With().Str("record", dnsName).Logger()
	txtLog.Debug().Msg("reading public key from DNS")
	txt, err := net.LookupTXT(dnsName)
	if err != nil {
		txtLog.Fatal().Err(err).Msg("public key txt lookup failed")
	}

	if len(txt) == 0 {
		txtLog.Fatal().Msg("txt lookup returned no records")
	}

	var allRecords []txtRecord
	hashAlg := crypto.SHA256 // default; overridden by 'a=' field
	scheme := schemeUnknown  // default; overridden by 'a=' field
	uniqP := make(map[int]bool)
	for _, r := range txt {
		if r == "" {
			txtLog.Fatal().Msg("empty txt record")
		}
		var record txtRecord
		pSeen := false

		txtLog.Debug().Str("txt", r).Msg("process txt record")
		fields := strings.Split(r, ",")
		for _, item := range fields {
			if len(item) < 2 {
				txtLog.Fatal().Str("item", item).Msg("txt record token too short")
			}
			if item[1] != '=' {
				txtLog.Fatal().Str("item", item).Msg("txt record token missing '='")
			}
			switch item[0] {
			case 'p':
				record.p, err = strconv.Atoi(item[2:])
				if err != nil {
					txtLog.Fatal().Err(err).Str("item", item[2:]).Msg("invalid number in txt record")
				}
				if _, found := uniqP[record.p]; found {
					txtLog.Fatal().Int("p", record.p).Msg("duplicate p number value")
				}
				uniqP[record.p] = true
				pSeen = true
			case 'a':
				var newHashAlg crypto.Hash
				var newScheme sigScheme
				switch item[2:] {
				case "RS256":
					newHashAlg = crypto.SHA256
					newScheme = schemeRSAPKCS1
				case "RS384":
					newHashAlg = crypto.SHA384
					newScheme = schemeRSAPKCS1
				case "RS512":
					newHashAlg = crypto.SHA512
					newScheme = schemeRSAPKCS1
				case "PS256":
					newHashAlg = crypto.SHA256
					newScheme = schemeRSAPSS
				case "PS384":
					newHashAlg = crypto.SHA384
					newScheme = schemeRSAPSS
				case "PS512":
					newHashAlg = crypto.SHA512
					newScheme = schemeRSAPSS
				case "ES256":
					newHashAlg = crypto.SHA256
					newScheme = schemeECDSA
				case "ES384":
					newHashAlg = crypto.SHA384
					newScheme = schemeECDSA
				case "ES512":
					newHashAlg = crypto.SHA512
					newScheme = schemeECDSA
				case "Ed25519":
					newHashAlg = 0
					newScheme = schemeEd25519
				default:
					txtLog.Fatal().Str("algorithm", item[2:]).Msg("unexpected algorithm in txt record")
				}
				if scheme != schemeUnknown && (scheme != newScheme || hashAlg != newHashAlg) {
					txtLog.Fatal().Str("algorithm", item[2:]).Msg("algorithm mismatch across txt records")
				}
				hashAlg = newHashAlg
				scheme = newScheme
			case 't':
				if item[2:] != "x509" {
					txtLog.Fatal().Str("keytoken", item[2:]).Msg("unexpected key token in txt record")
				}
			case 'd':
				record.d = item[2:]
			default:
				txtLog.Fatal().Str("item", item).Msg("unexpected data in txt record")
			}
		}
		if !pSeen {
			txtLog.Fatal().Str("fragment", r).Msg("txt record fragment missing p= field")
		}
		if record.d == "" {
			txtLog.Fatal().Str("fragment", r).Msg("txt record fragment missing d= field or d= is empty")
		}
		allRecords = append(allRecords, record)
	}
	if scheme == schemeUnknown {
		txtLog.Fatal().Msg("txt record does not define a=scheme")
	}
	if len(allRecords) == 0 {
		txtLog.Fatal().Msg("txt records contain no usable key data")
	}

	// DNS can and will provide records in random order, sort them
	sort.Slice(allRecords, func(i, j int) bool { return allRecords[i].p < allRecords[j].p })

	// Convert the text record to pem format
	var pubkeyBase64 string
	pubkeyBase64 = "-----BEGIN PUBLIC KEY-----\n"
	for i := range allRecords {
		if allRecords[i].d == "" {
			txtLog.Fatal().Int("p", allRecords[i].p).Msg("key fragment has empty d= value")
		}
		pubkeyBase64 += allRecords[i].d
	}
	pubkeyBase64 += "\n-----END PUBLIC KEY-----\n"

	// Extract certificate
	block, _ := pem.Decode([]byte(pubkeyBase64))
	if block == nil {
		txtLog.Fatal().Msg("public key pem decode failed")
	}
	x509parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		txtLog.Fatal().Err(err).Msg("public key x509 decode failed")
	}

	var pubKey crypto.PublicKey
	switch parsedKey := x509parsed.(type) {
	case *rsa.PublicKey:
		if scheme != schemeRSAPKCS1 && scheme != schemeRSAPSS {
			txtLog.Fatal().Msg("RSA key used with non-RSA algorithm")
		}
		pubKey = parsedKey
	case *ecdsa.PublicKey:
		if scheme != schemeECDSA {
			txtLog.Fatal().Msg("ECDSA key used with non-ECDSA algorithm")
		}
		pubKey = parsedKey
	case ed25519.PublicKey:
		if scheme != schemeEd25519 {
			txtLog.Fatal().Msg("Ed25519 key used with non-Ed25519 algorithm")
		}
		pubKey = parsedKey
	default:
		txtLog.Fatal().Msg("unsupported public key type")
	}

	return cachedCert{key: pubKey, scheme: scheme, hash: hashAlg}
}

func checkSignature(cert cachedCert, toBeVerified PostData) {
	log.Debug().Msg("checking signature")
	binarySig, err := base64.StdEncoding.DecodeString(toBeVerified.Sig)
	if err != nil {
		log.Fatal().Err(err).Msg("could not base64 decode")
	}

	var ok bool
	switch cert.scheme {
	case schemeRSAPKCS1:
		key, _ := cert.key.(*rsa.PublicKey)
		hashed := hashData(cert.hash, []byte(toBeVerified.Hash))
		ok = rsa.VerifyPKCS1v15(key, cert.hash, hashed, binarySig) == nil
	case schemeRSAPSS:
		key, _ := cert.key.(*rsa.PublicKey)
		hashed := hashData(cert.hash, []byte(toBeVerified.Hash))
		ok = rsa.VerifyPSS(key, cert.hash, hashed, binarySig, nil) == nil
	case schemeECDSA:
		key, _ := cert.key.(*ecdsa.PublicKey)
		hashed := hashData(cert.hash, []byte(toBeVerified.Hash))
		ok = ecdsa.VerifyASN1(key, hashed, binarySig)
	case schemeEd25519:
		key, _ := cert.key.(ed25519.PublicKey)
		ok = ed25519.Verify(key, []byte(toBeVerified.Hash), binarySig)
	default:
		log.Fatal().Msg("unsupported signature scheme")
	}

	if !ok {
		log.Error().Msg("verify public key failed")
	}
}
