![](https://travis-ci.com/xxxzsx/RSA-PEM-DER-to-JWK.svg?branch=master) ![](https://status.david-dm.org/gh/xxxzsx/RSA-PEM-DER-to-JWK.svg)

# RSA PEM/DER to JWK

RSA PEM/DER keys converter to JWK with no dependencies for both browser and Node.js.


## Installation
For Node.js run:
```
$ npm i rsa-pem-der-to-jwk
```

## Usage
```
// Require
const { rsaPemToJwk, base64ToHex } = require('rsa-pem-der-to-jwk')

// Import
import { rsaDerToJwk, hexToArrayBuffer } from 'rsa-pem-der-to-jwk'

// Browser
<script type="text/javascript" src="https://raw.githubusercontent.com/xxxzsx/RSA-PEM-DER-to-JWK/master/rsaPemDerToJwk.js">
```

You can store PEM key as a string/file or DER key as hex or base64 string in code and convert it to ArrayBuffer.

#### rsaPemToJwk(pemKey: string, type = 'public' | 'private', extraKeys = {})
Converts RSA PEM key to JWK.

#### rsaDerToJwk(derKey: ArrayBuffer, type = 'public' | 'private', extraKeys = {})
Converts RSA DER key (ArrayBuffer) to JWK.

## Additional functions

#### base64ToHex(base64)
Converts base64 string to hex string.

#### hexToBase64(hex)
Converts hex string to base64 string.

#### base64ToArrayBuffer(base64)
Converts base64 string to ArrayBuffer.

#### arrayBufferToBase64(buffer)
Converts ArrayBuffer string to base64.

#### hexToArrayBuffer(hex)
Converts hex string to ArrayBuffer.

#### arrayBufferToHex(buffer)
Converts ArrayBuffer to hex string.
