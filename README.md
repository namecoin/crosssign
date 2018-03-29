# crosssignnameconstraint

This tool applies a name constraint exclusion to a DER-encoded TLS trust
anchor via cross-signing.  The intended use case is to disallow a CA from
issuing certificates for a domain name that it has no legitimate business
issuing certificates for.  For example:

* Disallowing a public CA from issuing certificates for the `.bit` TLD used by
Namecoin.
* Disallowing a public CA from issuing certificates for a TLD controlled by
your corporate intranet.
* Disallowing your corporate intranet's CA from issuing certificates for a TLD
allocated by ICANN.

It currently only supports a single DNS domain name exclusion (because that's
all that Namecoin needed).  Pull requests that add additional flexibility for
the name constraints (e.g. multiple exclusions, permitted DNS domain names, or
non-DNS domain names) would be happily accepted and appreciated (even if it
breaks API backward-compatibility).

## Projects who use crosssignnameconstraint

Send a pull request if you'd like to be included.

* [tlsrestrictnss](https://github.com/namecoin/tlsrestrictnss/)

## Licence

crosssignnameconstraint is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

crosssignnameconstraint is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with crosssignnameconstraint.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
