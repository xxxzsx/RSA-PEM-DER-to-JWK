// Base64 to HEX string universal.
function base64ToHex(base64) {
    return typeof atob !== 'undefined' ?
        atob(base64).split('').map(byte => byte.charCodeAt(0).toString(16).padStart(2, '0')).join('') :
        Buffer.from(base64, 'base64').toString('hex')
}

// HEX string to Base64 universal.
function hexToBase64(hex) {
    const string = hex.match(/../g).map(byte => String.fromCharCode(parseInt(byte, 16))).join('')

    return typeof btoa !== 'undefined' ?
        btoa(string) :
        Buffer.from(string).toString('base64')
}

// Base64 to ArrayBuffer universal.
function base64ToArrayBuffer(base64) {
    return typeof atob !== 'undefined' ?
        Uint8Array.from(atob(base64), byte => byte.charCodeAt(0)).buffer :
        Uint8Array.from(Buffer.from(base64, 'base64')).buffer
}

// ArrayBuffer to Base64 universal.
function arrayBufferToBase64(buffer) {
    return typeof btoa !== 'undefined' ?
        btoa(String.fromCharCode(...new Uint8Array(buffer))) :
        Buffer.from(buffer).toString('base64')
}

// HEX to ArrayBuffer.
function hexToArrayBuffer(hex) {
    return Uint8Array.from(hex.match(/../g), byte => parseInt(byte, 16)).buffer
}

// ArrayBuffer to HEX.
function arrayBufferToHex(buffer) {
    return [...new Uint8Array(buffer)].map(byte => byte.toString(16).padStart(2, '0')).join('')
}


// PEM key to JWK.
function rsaPemToJwk(pem, type = undefined, extraKeys) {
    pem = pem.trim().split("\n").map(s => s.trim())

    // Check and remove RSA key header/footer
    let keyType = (/-----BEGIN(?: RSA)? (PRIVATE|PUBLIC) KEY-----/.exec(pem.shift()) || [])[1]
    if (!keyType || !RegExp(`-----END( RSA)? ${keyType} KEY-----`).exec(pem.pop()))
        throw Error('Headers not supported.')

    // Check requested JWK and given PEM types
    keyType = keyType.toLowerCase()
    if (type && type !== keyType)
        throw Error(`RSA type mismatch: requested ${type}, given ${keyType}.`)

    const der = base64ToArrayBuffer(pem.join(''))
    return rsaDerToJwk(der, keyType, extraKeys)
}

// DER key to JWK.
function rsaDerToJwk(der, type, extraKeys) {
    const buffer = new Uint8Array(der)

    let offset = {
        private: buffer[1] & 0x80 ? buffer[1] - 0x80 + 5 : 7,
        public: buffer[1] & 0x80 ? buffer[1] - 0x80 + 2 : 2
    }[type]

    // Read fields.
    const read = () => {
        let s = buffer[offset + 1]

        if (s & 0x80) {
            let n = s - 0x80
            s = new DataView(buffer.buffer)[
                ['getUint8', 'getUint16'][n - 1]
            ](offset + 2)

            offset += n
        }
        offset += 2

        return buffer.slice(offset, offset += s)
    }

    // URL-safe base64.
    const readBase64 = () =>
        arrayBufferToBase64(read())
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '')

    return {
        kty: 'RSA',
        ...extraKeys,
        // The public part is always present
        n: readBase64(),      // modulus
        e: readBase64(),      // public exponent
        // Read private part
        ...type === 'private' && {
            d: readBase64(),  // private exponent
            p: readBase64(),  // prime 1
            q: readBase64(),  // prime 2
            dp: readBase64(), // exponent 1
            dq: readBase64(), // exponent 2
            qi: readBase64()  // coefficient
        }
    }
}


if (typeof module !== 'undefined') {
    module.exports = {
        base64ToHex,
        hexToBase64,
        base64ToArrayBuffer,
        arrayBufferToBase64,
        hexToArrayBuffer,
        arrayBufferToHex,
        rsaPemToJwk,
        rsaDerToJwk
    }
}