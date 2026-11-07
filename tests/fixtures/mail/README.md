# Mail fixtures

`rfc8463-signed.eml`: the example message of RFC 8463 (Appendix A), signed
by `football.example.com` with Ed25519 (`brisbane`) and RSA (`test`), as
shipped in dkimpy's test data (dkimpy 1.1.8, zlib licence: "This software
is provided 'as-is' ... Permission is granted to anyone to use this software
for any purpose"). The public keys are in `tests/test_mail_dns.py`.

`dist-list.pst.gz`, `example-2013.ost.gz`: the test files of java-libpst
(https://github.com/rjohnsondev/java-libpst, src/test/resources; licensed
under the LGPL and the Apache License 2.0), gzip-compressed. Its tests state
what they hold: node 2097188 is a distribution list, 2097348 an
appointment; in the 2013 OST the Inbox (node 8578) has two messages, and
node 2097284's HTML body is Outlook's test-message sentence.
