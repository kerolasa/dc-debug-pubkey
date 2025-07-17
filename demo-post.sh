#!/bin/bash

if ! [ -x ./dc-debug-pubkey ]; then
	echo "./dc-debug-pubkey is missing, please run 'go build' first"
	exit 1
fi

# This random string represents payload that needs validation.  In real Domain
# Connect the payload is domain=...&host=...  and so on apply query string.
# See: https://github.com/Domain-Connect/spec/blob/master/Domain%20Connect%20Spec%20Draft.adoc#digitally-sign-requests
to_be_validated="$(openssl rand -base64 48 | tr -d /)"

printf "$to_be_validated" >| "./$to_be_validated"
openssl dgst -sha256 -sign ./example.private-key.pem -out "./$to_be_validated.signed" "./$to_be_validated"
sig="$(base64 < ./$to_be_validated.signed | tr -d '\n')"

# Create a post file
cat >| ./$to_be_validated.post <<- EOF
        {
          "domain": "domainconnect-DNS-4310-staging.lavington25.com",
          "sig": "$sig",
          "hash": "$to_be_validated"
        }
EOF

# Check it works
./dc-debug-pubkey --loglevel debug --postdata ./$to_be_validated.post ./example.template.json

# Remove temporary files
rm -fv ./$to_be_validated.post ./$to_be_validated.signed ./$to_be_validated
