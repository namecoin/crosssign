# crosssign

This library cross-signs a DER-encoded X.509 CA.  It doesn't require a
signature or CSR from the CA to be cross-signed (meaning you can use it without
the knowledge or permission of the CA to be cross-signed), and it doesn't try
to parse the contents of either certificate (meaning you can use X.509 features
that Go's standard library doesn't know how to parse, and they will be passed
through intact).

A CLI tool is also provided.

## Requirements

We haven't tested crosssign with Go versions below 1.10.0, and there is [reason
to believe](https://github.com/namecoin/crosssignnameconstraint/issues/2) that
Go 1.9.x handles X.509 parsing incorrectly.  It isn't clear whether the Go
1.9.x issues impact crosssign, since crosssign doesn't try to parse most X.509
features and is therefore immune to a lot of Go standard library issues.  That
said, it's probably wise to only use crosssign with Go 1.10.0 and higher.

## Projects who use crosssign

Send a pull request if you'd like to be included.

* [crosssignnameconstraint](https://github.com/namecoin/crosssignnameconstraint/)
* [tlsrestrictnss](https://github.com/namecoin/tlsrestrictnss/)

## Licence

crosssign is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

crosssign is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with crosssign.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
