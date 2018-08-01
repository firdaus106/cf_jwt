# Coldfusion JWT Library

A ColdFusion CFC to manage the encoding and decoding of JWTs (JSON Web Tokens)

## Getting Started

Example usage (using CFM):

```coldfusion
<cfset APPLICATION.jwt.init('secretkey')>
<cfset payload = structNew()>
<cfset payload["iat"] = DateDiff("s", DateConvert("utc2Local", "January 1 1970 00:00"), now())>
<cfset payload["exp"] = DateDiff("s", DateConvert("utc2Local", "January 1 1970 00:00"), dateAdd('s', 15, now()))>
<cfset payload["mydata"] = "Data goes here!">

<!--- The encoded token (returns string) --->
<cfset encodedToken = APPLICATION.jwt.encode(payload: payload)>

<!--- The decoded token (returns CFML data) --->
<cftry>
    <cfset decodedToken = APPLICATION.jwt.decode(token: encodedToken)>
    <cfcatch>
        <cfoutput>ERROR! #cfcatch.type# - #cfcatch.message#</cfoutput>
    <cfcatch>
</cftry>

<!--- The verification of the token (returns true / false) --->
<cfset verifyToken = APPLICATION.jwt.verify(token: encodedToken)>
```

In the example above, the JWT library was initialized using `cfobject` to `APPLICATION.jwt`. There are examples how to encode, decode and verify the JSON Web Token.

Testing
----------------
The component has been tested on Adobe ColdFusion 10 as for now. Currently the testbox is not being updated/used by me.


Thanks
----------------

This component is based upon the original https://github.com/jsteinshouer/cf-jwt-simple and forked from https://github.com/coldfumonkeh/cf_jwt


MIT License

Copyright (c) 2018 Yusof Firdaus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
