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

// URL-safe base64.
function base64Url(base64) {
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
}


// PEM unpack.
function rsaUnpack(pem) {
    pem = pem.split("\n").map(s => s.trim())

    // Check and remove RSA key header/footer.
    let type = (/-----BEGIN RSA (PRIVATE|PUBLIC) KEY-----/.exec(pem.shift()) || [])[1]
    if (!type || pem.pop() !== '-----END RSA ' + type + ' KEY-----')
        throw Error('Headers not supported.')

    const der = base64ToArrayBuffer(pem.join(''))
    type = type.toLowerCase()

    return derUnpack(der, type)
}

// DER unpack.
function derUnpack(der, type = 'public') {
    const buf = new Uint8Array(der)
    const fields = {}

    let offset = {
        private : buf[1] & 0x80 ? buf[1] - 0x80 + 5 : 7,
        public : buf[1] & 0x80 ? buf[1] - 0x80 + 2 : 2
    }[type]

    function read() {
        let s = buf[offset + 1]

        if (s & 0x80) {
            var n = s - 0x80
            s = new DataView(buf.buffer)[['getUint8', 'getUint16'][n - 1]](offset + 2)
            offset += n
        }

        offset += 2

        const b = buf.slice(offset, offset + s)
        offset += s
        return b
    }

    fields.modulus = read()
    fields.bits = (fields.modulus.length - 1) * 8 + Math.ceil(Math.log2(fields.modulus[0] + 1))
    fields.publicExponent = parseInt(arrayBufferToHex(read()), 16)

    if (type === 'private') {
        fields.privateExponent = read()
        fields.prime1 = read()
        fields.prime2 = read()
        fields.exponent1 = read()
        fields.exponent2 = read()
        fields.coefficient = read()
    }

    for (const k of Object.keys(fields))
        if (fields[k] instanceof Uint8Array)
            fields[k] = base64Url(arrayBufferToBase64(fields[k]))

    return fields
}


// PEM key to JWK.
function rsaPemToJwk(pem, type = undefined, extraKeys) {
    const key = rsaUnpack(pem)
    return keyToJwk(key, type, extraKeys)
}

// DER key to JWK.
function rsaDerToJwk(der, type = undefined, extraKeys) {
    const key = derUnpack(der, type)
    return keyToJwk(key, type, extraKeys)
}

function keyToJwk(key, type = undefined, extraKeys) {
    type = type || (key.privateExponent !== undefined ? 'private' : 'public')

    // Requested JWK and given PEM does not match
    if (type === 'private' && !key.privateExponent || type === 'public' && key.privateExponent)
        throw Error(`RSA type mismatch: requested ${type}, given ${key.privateExponent ? 'private' : 'public'}.`)

    // Make the public exponent into a buffer of minimal size
    const expSize = Math.ceil(Math.log(key.publicExponent) / Math.log(256))
    key.exp = new Uint8Array(expSize)
    let v = key.publicExponent

    for (let i = expSize - 1; i >= 0; i--) {
        key.exp[i] = v % 256
        v = Math.floor(v / 256)
    }
    key.exp = base64Url(arrayBufferToBase64(key.exp))

    return {
        kty: 'RSA',
        ...extraKeys,
        // The public part is always present
        n: key.modulus,
        e: key.exp,
        // Add private part
        ...type === 'private' && {
            d: key.privateExponent,
            p: key.prime1,
            q: key.prime2,
            dp: key.exponent1,
            dq: key.exponent2,
            qi: key.coefficient
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