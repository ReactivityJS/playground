/**
 * SEA
 * A crypto api wrapper inspired by Gun SEA module (https://github.com/amark/gun/blob/master/sea.js)
 */

// import needed convert helpers...
import { StrToUint8, Uint8ToStr, AbToB64, B64ToAb, ObjToB64, B64ToObj, StrToAb, AbToStr, B64ToStr, StrToB64, ObjToJson, JsonToObj } from './DataTypeConverter.mjs'

const
cryptoSubtle = globalThis.crypto.subtle,
signPairParams = [
    //{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, 
    { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },  // shorter pub and less secure, but supported by PHP openssl
    true, 
    ['sign', 'verify']
],
cryptPairDeriveParams = [
    { name: 'ECDH', namedCurve: 'P-256' }, 
    true, 
    ['deriveKey']
],
cryptPairParams = [
    { name: 'AES-GCM', length: '256' },
    false,
    ['encrypt', 'decrypt']
],
passphraseKeyParams = [
    { name: "PBKDF2", salt: StrToUint8("SaltString..."), iterations: 1000, hash: "SHA-256" },   // salt string ?!
    false,
    ['deriveKey']
],
tranferKeyParams = { 
    pub: { type: 'spki', exp: AbToB64, imp: B64ToAb, opt: [ signPairParams[0], signPairParams[1], [signPairParams[2][1]] ] },
    priv: { type: 'jwk', exp: ObjToB64, imp: B64ToObj, opt: [ signPairParams[0], signPairParams[1], [signPairParams[2][0]] ] },
    epub: { type: 'spki', exp: AbToB64, imp: B64ToAb, opt: [ cryptPairDeriveParams[0], cryptPairDeriveParams[1], [] ] },
    epriv: { type: 'jwk', exp: ObjToB64, imp: B64ToObj, opt: [ cryptPairDeriveParams[0], cryptPairDeriveParams[1], cryptPairDeriveParams[2] ] }
},

/**
 * Signing data
 * 
 * @param {String} data - Message to sign
 * @param {CryptoKey} signerPriv - Private key to use for signing
 * @return {String} Base64 encoded signature
 */
sign = async (data, signerPriv) => {
    if(!signerPriv) throw "No signing key pair!"
    return StrToB64(AbToStr(await cryptoSubtle.sign(
        signPairParams[0], 
        signerPriv, 
        StrToAb(data)
    )))
},

/**
 * Verify data with signature
 * 
 * @param {String} data - Message to check
 * @param {String} signedData - Signature to match
 * @param {CryptoKey} signerPub - Public sign key to use
 * @return {Boolean} Signature verification result
 */
verify = async (data, signedData, signerPub) => {
    return await cryptoSubtle.verify(
        signPairParams[0], 
        signerPub, 
        StrToAb(B64ToStr(signedData)), 
        StrToAb(data)
    )
},

/**
 * Create a password based CryptoKey for 1:n encryption
 * 
 * @param {String} password Password String
 * @return {CryptoKey} Password based secret for de-/encryption
 * 
 * @todo Remove hardcoded params (salt, iterations, ...)
 * 
 * shared secret from password:
 * - https://medium.com/@lina.cloud/password-based-client-side-crypto-6fbe4b389bac
 */
passphrase = async (password) => {
    return await cryptoSubtle.deriveKey(
        passphraseKeyParams[0],
        await cryptoSubtle.importKey(
            'raw',
            StrToUint8(password),
            ...passphraseKeyParams
        ),
        ...cryptPairParams
    )
},

/**
 * Create a secret for de-/encryption
 * 
 * @param {CryptoKey|String} foreignPub - Public encryption key of recipient OR password string
 * @param {CryptoKey} epriv - Senders private encryption key
 * @return {yptoKey} Secret to use for de-/encryption
 */
secret = async (foreignPub, epriv) => {
    if(typeof foreignPub == 'string') {
        return await passphrase(foreignPub)
    }
    return await cryptoSubtle.deriveKey(
        { ...cryptPairDeriveParams[0], public: foreignPub }, 
        epriv, 
        ...cryptPairParams
    )
},

/**
 * Encrypt with derivedKey / Secret
 * 
 * @param {String} data - Message to encrypt
 * @param {CryptoKey} foreignPub - Recipients epub key
 * @param {CryptoKey} epriv - Senders private encryption key
 * @return {String} Stringified encData + iv
 * 
 * @todo Object instead of stringified?
 */
encrypt = async (data, foreignPub, epriv) => {
    let
    derivedKey = await secret(foreignPub, epriv),
    iv = crypto.getRandomValues(new Uint8Array(12)),
    encData = await cryptoSubtle.encrypt(
        { ...cryptPairParams[0], iv }, 
        derivedKey, 
        StrToUint8(data)
    ),
    returnData = ObjToJson({
        enc: AbToB64(encData),  
        iv: StrToB64(Uint8ToStr(iv))
    })
    return returnData
},

/**
 * Decrypt with derivedKey / Secret
 * 
 * @param {String} encDataIn - Stringified encData + iv
 * @param {CryptoKey} foreignPub - Senders public encryption key
 * @param {CryptoKey} epriv - Recipients private encryption key
 * @return {String} Decrypted message
 */
decrypt = async (encDataIn, foreignPub, epriv) => {
    let 
    derivedKey = await secret(foreignPub, epriv),
    parsedData = JsonToObj(encDataIn),
    decodedIV = StrToUint8(B64ToStr(parsedData.iv)),
    decrytedData = await cryptoSubtle.decrypt(
        { ...cryptPairParams[0], iv: decodedIV }, 
        derivedKey, 
        B64ToAb(parsedData.enc)
    )
    return AbToStr(decrytedData)
},

/**
 * Generate sea user key pairs
 * { pub, priv, epub, epriv }
 * 
 * @return {Object} sea user key pairs 
 */
pair = async () => {
    let 
    signPair = await cryptoSubtle.generateKey(...signPairParams),
    derivePair = await cryptoSubtle.generateKey(...cryptPairDeriveParams)
    return { 
        pub: signPair.publicKey, 
        priv: signPair.privateKey, 
        epub: derivePair.publicKey, 
        epriv: derivePair.privateKey 
    }
},

/**
 * Export CryptoKey to base64
 * 
 * @param {cryptoKey} cryptoKey - Key to export to base64
 * @param {String} seaUse - One of pub, priv, epub or epriv
 * @return {String} Base64 encoded and exported CryptoKey
 */
exportKey = async (cryptoKey, seaUse = 'pub') => tranferKeyParams[seaUse].exp(
    await cryptoSubtle.exportKey(
        tranferKeyParams[seaUse].type, 
        cryptoKey
    )
),

/**
 * Import CryptoKey
 * 
 * @param {String} base64key - Base64 key to import
 * @param {String} seaUse - One of pub, priv, epub or epriv
 * @return {CryptoKey} Imported CryptoKey
 */
importKey = async (base64key, seaUse = 'pub') => await cryptoSubtle.importKey(
    tranferKeyParams[seaUse].type, 
    tranferKeyParams[seaUse].imp(base64key), 
    ...tranferKeyParams[seaUse].opt
),

/**
 * Backup full sea user pairs
 * 
 * @param {Object} pairs - sea pair object
 * @return {Object} Stringified exported CryptoKeys 
 */
backup = async (pair) => {
    let exportedPairs = {}
    for (const [seaUse, cryptoKey] of Object.entries(pair)) {
        //console.log('BACKUP', seaUse, cryptoKey)
        exportedPairs[seaUse] = await exportKey(cryptoKey, seaUse)
    }
    return exportedPairs
},

/**
 * Restore full sea user pairs from backup
 * 
 * @param {Object} exportedPairs - Object with exported CryptoKeys
 * @return {Object} Imported sea user pair CryptoKeys
 * 
 * @todo handle alias / ignore additional properties?
 */
restore = async (exportedPairs) => {
    let importedPairs = {}
    for (const [seaUse, exportedKey] of Object.entries(exportedPairs)) {
        //console.log('RESTORE', seaUse, exportedKey)
        importedPairs[seaUse] = await importKey(exportedKey, seaUse)
    }
    return importedPairs
},

/**
 * Create uuid
 * Create a random 36 character v4 UUID string
 * 
 * @return {String} uuid v4 with 36 characters
 */
uuid = () => globalThis.crypto.randomUUID(),

/**
 * crypto key pair based idenditiy
 * Identity like user or device based on a full key pair with priv and pub keys
 * 
 * @param {Object} keypair Idendity pair
 */
User = class {
    #eprivKey
    #privKey
    epubKey
    pubKey
    epub
    pub
    constructor(keypair) {
        if(this instanceof Contact) {
            this.contact = undefined
            this.backup = undefined
        }
        if(keypair && keypair.priv) {
            this.#eprivKey = keypair.epriv
            this.#privKey = keypair.priv
            this.epubKey = keypair.epub
            this.pubKey = keypair.pub
        }
        ;(async () => {
            if(typeof keypair === 'string') {
                // import an backuped pair...
                keypair = await restore(JSON.parse(keypair))
                this.#eprivKey = keypair.epriv
                this.#privKey = keypair.priv
                this.epubKey = keypair.epub
                this.pubKey = keypair.pub
            } else if(!keypair) {
                // create new pair...
                keypair = await pair()
                this.#eprivKey = keypair.epriv
                this.#privKey = keypair.priv
                this.epubKey = keypair.epub
                this.pubKey = keypair.pub
            }
            this.pub = await exportKey(keypair.pub)
            this.epub = await exportKey(keypair.epub)
            Object.freeze(this)
        })()
    }

    async encrypt(data, foreignPub = this.epubKey) {
        return await encrypt(data, foreignPub, this.#eprivKey)
    }

    async decrypt(cryptData, foreignPub = this.epubKey) {
        return await decrypt(cryptData, foreignPub, this.#eprivKey)
    }

    async sign(data) {
        return await sign(data, this.#privKey)
    }

    async verify(data, signature, signerPub = this.pubKey) {
        return await verify(data, signature, signerPub)
    }

    contact(pub, epub) {
        return new Contact({ pub, epub, priv: this.#privKey, epriv: this.#eprivKey })
    }

    async backup() {
        return JSON.stringify(await backup({ pub: this.pubKey, epub: this.epubKey, priv: this.#privKey, epriv: this.#eprivKey }))
    }
},

/**
 * crypto key pair based foreign idenditiy reference
 * Helper to interact with your User private keys and foreign Contact public keys
 * 
 * @param {Object} keypair Pair with foreign public keys and Users private keys
 */
Contact = class extends User {}

export {
    sign, 
    verify, 
    passphrase, 
    secret, 
    encrypt, 
    decrypt, 
    pair, 
    exportKey, 
    importKey, 
    backup, 
    restore,
    uuid,
    User,
    Contact
}