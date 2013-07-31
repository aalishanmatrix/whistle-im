/**
 * @fileoverview whistle client crypt.
 * All rights reserved.
 * @author Daniel Wirtz <dcode@dcode.io>
 */

// Crypt worker
if (typeof this.window === 'undefined') {
    var whistle = {};
    importScripts('../forge.min.js', '../bcrypt.min.js');
    self.addEventListener("message", function(e) {
        var data = e.data;
        var method = data.shift();
        try {
            switch (method) {
                case 'start': break;
                default: self.postMessage([null, whistle.crypt[method].apply(this, data)]);
            }
        } catch (err) {
            self.postMessage([{ "message": err.message }]); // Mimic error
        }
    });
}

// Crypt module
(function(whistle, forge, bcrypt, global) {
    "use strict";

    var pki = forge.pki,
        random = forge.random,
        rsa = forge.rsa,
        aes = forge.aes,
        sha1 = forge.sha1,
        util = forge.util;

    /**
     * Asynchronous workers.
     * @type {Array.<Worker>}
     */
    var workers = [];
    if (typeof global.Worker !== 'undefined') {
        for (var i=0; i<3; i++) { // Let's expect 4 cores and use 3
            var worker = new Worker("/js/whistle/crypt.js");
            worker.working = false;
            workers[i] = worker;
            worker.postMessage(["start"]);
        }
    }

    /**
     * Asynchronous work queue.
     * @type {Array.<Array>}
     */
    var work = [];

    /**
     * Executes an asynchronous task.
     */
    function doWork() {
        if (work.length == 0) return;
        var worker = null; for (var i=0; i<workers.length; i++) {
            if (!workers[i].working) {
                worker = workers[i];
                break;
            }
        }
        if (!worker) return;
        worker.working = true;
        var args = work.shift();
        var callback = args.pop();
        worker.onmessage = function(e) {
            callback.apply(this, e.data);
            worker.working = false;
            doWork();
        };
        worker.postMessage(args);
    }

    /**
     * Processes a normally synchronous crypt task asynchronously.
     * @param {string} cmd Crypt method
     * @param {...*} varargs Variable arguments
     * @param {function(Error, ...*)} callback Callback
     */
    function async(method, args) {
        args = Array.prototype.slice.call(args);
        if (workers.length > 0) { // A life in luxury!
            args.unshift(method);
            work.push(args);
            doWork();
        } else { // What a dump.
            var callback = args.pop();
            setTimeout(function() {
                try {
                    callback(null, whistle.crypt[method].apply(this, args));
                } catch (err) {
                    callback(err);
                }
            }, 1);
        }
    }

    /**
     * crypt namespace.
     * @type {Object.<string,*>}
     */
    var crypt = {};

    /**
     * RSA bits.
     * @type {number}
     * @const
     */
    crypt.RSA_BITS = 2048;

    /**
     * RSA bytes.
     * @type {number}
     * @const
     */
    crypt.RSA_BYTES = crypt.RSA_BITS/8;

    /**
     * AES bits.
     * @type {number}
     * @const
     */
    crypt.AES_BITS = 256;

    /**
     * AES bytes.
     * @type {number}
     * @const
     */
    crypt.AES_BYTES = crypt.AES_BITS/8;

    /**
     * Asynchronously generates a private and public key pair.
     * @param {number} bits Key size
     * @param {number} exp Public exponent
     * @param {function(Error, Array.<string>)} callback
     */
    function generateAsync(bits, exp, callback) {
        var state = rsa.createKeyPairGenerationState(bits, exp);
        var step = function() {
            try {
                if (!rsa.stepKeyPairGenerationState(state, 500 /* ms */)) {
                    setTimeout(step, 0);
                } else {
                    var keys = [];
                    keys.push(pki.privateKeyToPem(state.keys.privateKey));
                    keys.push(pki.publicKeyToPem(state.keys.publicKey));
                    callback(null, keys);
                }
            } catch (err) {
                callback(err);
            }
        };
        setTimeout(step, 0);
    }

    /**
     * Generates a private and public key pair.
     * @param {(number|function(Error, Array.<string>))=} bits Bits
     * @param {function(Error, Array.<string>)=} callback
     * @returns {Array.<string>|undefined} Private and public key if callback has been omitted
     */
    crypt.generateKeyPair = function(bits, callback) {
        if (typeof bits === 'function') {
            callback = bits;
            bits = null;
        }
        bits = bits || crypt.RSA_BITS;
        var exp = 0x10001; // 65537

        if (callback) { // Async

            // Try to use the device's native generator if available
            if (whistle.native.available) {
                whistle.native.genkeys(bits, exp, function(err, keys) {
                    if (err) {
                        generateAsync(bits, exp, callback);
                        return;
                    }
                    callback(null, keys);
                })
            } else {
                generateAsync(bits, exp, callback);
            }

        } else { // Sync (actually not used)

            var pair = rsa.generateKeyPair({bits: bits, e: exp});
            var keys = [];
            keys.push(pki.privateKeyToPem(pair.privateKey));
            keys.push(pki.publicKeyToPem(pair.publicKey));
            return keys;
        }
    };

    /**
     * Encrypts some data.
     * @param {string} data Data to encrypt
     * @param {string} publicKey Public key to use for encrypting
     * @param {string=} privateKey Private key to use for signing
     * @returns {{enc: string, sig: string|null}} Encrypted data and signature
     */
    crypt.encrypt = function(data, publicKey, privateKey) {
        if (typeof arguments[arguments.length-1] === 'function') {
            async("encrypt", arguments);
            return;
        }
        publicKey = pki.publicKeyFromPem(publicKey);
        data = util.encodeUtf8(data);
        var key = random.getBytesSync(crypt.AES_BYTES);
        var iv = random.getBytesSync(16); // 128 bit block size
        var cipher = aes.createEncryptionCipher(key);
        cipher.start(util.createBuffer(iv, "raw"));
        cipher.update(util.createBuffer(data, "raw"));
        cipher.finish();
        var enc = publicKey.encrypt(key+iv, "RSA-OAEP") + cipher.output.getBytes();
        var sig = null;
        if (privateKey) {
            sig = this._sign(/* raw */ enc, privateKey);
        }
        return {
            "enc": util.encode64(enc),
            "sig": sig ? util.encode64(sig) : null
        };
    };

    /**
     * Signs some data.
     * @param {string} data Data to sign as a byte string
     * @param {string} privateKey Private key to use for signing
     * @returns {string} Signature as a byte string
     * @private
     */
    crypt._sign = function(data, privateKey) {
        privateKey = pki.privateKeyFromPem(privateKey);
        var md = sha1.create();
        md.update(data, 'raw');
        return privateKey.sign(md);
    };

    /**
     * Decrypts some data.
     * @param {string} enc Base64 encoded encrypted data
     * @param {string} privateKey Private key to use for decrypting
     * @param {string=} sig Base64 encoded signature
     * @param {string=} publicKey Public key to use for verifying
     * @returns {{dec: string, ver: boolean|null}} Decrypted data and verification result
     */
    crypt.decrypt = function(enc, privateKey, sig, publicKey) {
        if (typeof arguments[arguments.length-1] === 'function') {
            async("decrypt", arguments);
            return;
        }
        privateKey = pki.privateKeyFromPem(privateKey);
        enc = util.decode64(enc);
        var md = sha1.create();
        md.update(enc, "raw");
        var ver = null;
        if (sig && publicKey) {
            ver = crypt._verify(/* raw */ md, /* raw */ util.decode64(sig), publicKey);
        }
        var aesData = enc.substring(0, crypt.RSA_BYTES);
        enc = enc.substring(crypt.RSA_BYTES);
        aesData = privateKey.decrypt(aesData, "RSA-OAEP");
        var key = aesData.substring(0, crypt.AES_BYTES);
        var iv = aesData.substring(crypt.AES_BYTES);
        var cipher = aes.createDecryptionCipher(key);
        cipher.start(util.createBuffer(iv, "raw"));
        cipher.update(util.createBuffer(enc, "raw"));
        cipher.finish();
        return {
            "dec": util.decodeUtf8(cipher.output.getBytes()),
            "ver": ver
        };
    };

    /**
     * Verifies some raw data.
     * @param {string|Object} data Data as a byte string or message digest object
     * @param {string} signature Signature as a byte string
     * @param {string} publicKey Public key to use for verifying
     * @returns {boolean}
     * @private
     */
    crypt._verify = function(data, signature, publicKey) {
        publicKey = pki.publicKeyFromPem(publicKey);
        var md;
        if (typeof data === 'string') {
            md = sha1.create();
            md.update(data, 'raw');
        } else {
            md = data;
        }
        return publicKey.verify(md.digest().getBytes(), signature);
    };

    /**
     * Encrypts a private key with a password.
     * @param {string} key Private key
     * @param {string} password Password
     * @returns {string} Encrypted private key
     */
    crypt.encryptPrivateKey = function(key, password) {
        if (typeof arguments[arguments.length-1] === 'function') {
            async("encryptPrivateKey", arguments);
            return;
        }
        key = pki.privateKeyFromPem(key);
        key = pki.encryptRsaPrivateKey(key, password, {
            'algorithm': 'aes128' // CBC
        });
        return key;
    };

    /**
     * Decrypts an encrypted private key using a password.
     * @param {string} key Private key
     * @param {string} password Password
     * @returns {string} Decrypted private key
     * @throws {Error} If the key cannot be decrypted
     */
    crypt.decryptPrivateKey = function(key, password) {
        if (typeof arguments[arguments.length-1] === 'function') {
            async("decryptPrivateKey", arguments);
            return;
        }
        key = pki.decryptRsaPrivateKey(key, password);
        if (!key) {
            throw(new Error("keypass"));
        }
        return pki.privateKeyToPem(key);
    };

    /**
     * Encrypts a vcard.
     * @param {string} data Vcard
     * @param {string} publicKey Public key to encrypt with
     * @returns {string} Encrypted vcard
     * @throws {Error} If encryption fails
     */
    crypt.encryptVcard = function(vcard, publicKey) {
        if (typeof arguments[arguments.length-1] === 'function') {
            async("encryptVcard", arguments);
            return;
        }
        if (vcard === null || vcard === "") {
            return null;
        }
        vcard = JSON.stringify(vcard);
        vcard = crypt.encrypt(vcard, publicKey).enc;
        return vcard;
    };

    /**
     * Decrypts a vcard.
     * @param {string} data} Encrypted vcard
     * @param {string} privateKey Private key to decrypt with
     * @returns {*} Decrypted vcard
     * @throws {Error} If decryption fails
     */
    crypt.decryptVcard = function(data, privateKey) {
        if (typeof arguments[arguments.length-1] === 'function') {
            async("decryptVcard", arguments);
            return;
        }
        if (data === null || data === "") {
            whistle.vcard = null;
            return;
        }
        var vcard = crypt.decrypt(data, privateKey).dec;
        vcard = JSON.parse(vcard);
        return vcard;
    };

    /**
     * Hashes a password.
     * @param {string} pass Password to hash
     * @param {string|number} salt Salt or number of rounds (i.e. year-2000)
     * @param {function(Error, string)=} callback
     * @returns {string|undefined} Hash
     */
    crypt.hash = function(pass, salt, callback) {
        if (typeof arguments[arguments.length-1] === 'function') {
            if (typeof salt === 'number') {
                // WebWorkers don't have window.crypto, so salt it here
                arguments[1] = bcrypt.genSaltSync(salt);
            }
            async("hash", arguments);
            return;
        }
        return bcrypt.hashSync(pass, salt); // Much faster than the async version
    };

    /**
     * Gets some random bytes.
     * @param {number} len Length
     * @returns {string} Random bytes
     */
    crypt.random = function(len) {
        return random.getBytesSync(len); // Uses Web Crypto API if available
    };

    // Web Crypto API Polyfill for bcrypt
    if (!global.crypto) global.crypto = {};
    if (!global.crypto.getRandomValues) {
        global.crypto.getRandomValues = function(array) {
            var bytes = crypt.random(array.length);
            for (var i=0; i<array.length; i++) {
                array[i] = bytes.charCodeAt(i);
            }
        };
    }

    crypt.bcrypt = bcrypt;

    whistle.crypt = crypt;

})(whistle, forge, dcodeIO.bcrypt, this);
