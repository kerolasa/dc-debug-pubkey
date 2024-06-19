## Domain Connect service provider

This tool aims to help Domain Connect service providers to debug syncPubKeyDomain
setup.  Typical usage should look something like below.

```
go install github.com/kerolasa/dc-debug-pubkey@latest
$GOPATH/dc-debug-pubkey ./private_key.pem ./exampleservice.domainconnect.org.template1.json hash-payload-in-the-POST-data
```

The private key is generated by the service provider.  See exampleservice
link for instructions how to do that.  The
[template](https://github.com/Domain-Connect/Templates/blob/master/exampleservice.domainconnect.org.template1.json)
is the data service provider gives to DNS Providers to, and has information
what TXT record the DNS Providers need to use to verify updates.

See also:

* https://github.com/Domain-Connect/spec/blob/master/Domain%20Connect%20Spec%20Draft.adoc#digitally-sign-requests
* https://exampleservice.domainconnect.org/sig