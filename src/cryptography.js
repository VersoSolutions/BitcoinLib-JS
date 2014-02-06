/**
 * Main cryptography features
 */
Verso.Cryptography = (function () {

    sjcl.random.setDefaultParanoia(6); // 256 bits of entropy

    // Collect additional entropy from sources of noise
    if (sjcl.random.isReady() === 0) {
        sjcl.random.startCollectors();
        sjcl.random.addEventListener("seeded", function() {
            sjcl.random.stopCollectors();
        });
    }

    var entropy = [];
    /**
     * Add entropy to the RNG (without stopping entropy collection)
     *
     * @memberOf Verso.Cryptography
     * @param  {Array} ba Entropic byte array
     */
    var addPureEntropy = function (ba) {
        entropy = entropy.concat(ba);
    };

    /**
     * Returns true if the RNG has enough entropy
     *
     * @memberOf Verso.Cryptography
     * @return {ByteArray} Returns true if the RNG has enough entropy
     */
    var isRngReady = function (paranoia) {
        return sjcl.random.isReady(paranoia);
    };

    /**
     * Random bytes generator
     *
     * @memberOf Verso.Cryptography
     * @param  {Integer}   length     The desired length
     * @param  {Integer}   [paranoia] The desired level of paranoia
     * @return {ByteArray}            The generated random byte array
     */
    var randomBytes = function (length, paranoia) {
        if (paranoia === undefined)
            paranoia = 0;

        var words;

        try {
            if (!sjcl.random.isReady(paranoia) && entropy.length > 0) {
                sjcl.random.addEntropy(Verso.Encoding.bytesToWords(entropy), 8 * entropy.length);
                entropy = [];
            }

            words = sjcl.random.randomWords(Math.ceil(length/4), paranoia);
        }
        catch (e) {
            throw new Verso.Error("Insufficient entropy!");
        }

        return Verso.Encoding.wordsToBytes(words).slice(0,length);
    };

    /**
     * Password-based key derivation function as defined in PKCS #5. Always returns a 256-bit key.
     *
     * @memberOf Verso.Cryptography
     * @param  {String}    password   The password
     * @param  {ByteArray} salt       The salt
     * @param  {Integer}   iterations The number of iterations
     * @return {ByteArray}            The derived key
     */
    var PBKDF2 = function (password, salt, iterations) {
        var hmacSHA1 = function (key) { // SJCL uses HMAC-SHA256 by default, we use SHA-1 for compatibility reasons
            var hasher = new sjcl.misc.hmac(key, sjcl.hash.sha1);
            this.encrypt = function () { return hasher.encrypt.apply(hasher, arguments); };
        };

        // TEMP: Should convert password from UTF8

        return Verso.Encoding.wordsToBytes(
                 sjcl.misc.pbkdf2( // SJCL implementation of PBKDF2 much more efficient than CryptoJS implementation
                   password,
                   Verso.Encoding.bytesToWords(salt),
                   iterations,
                   256,
                   hmacSHA1));
    };

    /**
     * Colin Percival's scrypt password-based key derivation function.
     *
     * @memberOf Verso.Cryptography
     * @param {String}     password The password
     * @param {ByteArray}  salt     The salt
     * @param {Integer}    N        CPU cost parameter
     * @param {Integer}    r        Memory cost parameter
     * @param {Integer}    p        Parallelization cost
     * @param {Integer}    L        Key length in bits
     * @return {ByteArray}          The derived key
     *
     * This code is adapted from https://github.com/cheongwy/node-scrypt-js
     *
     * The following license applies only to the function "scrypt" defined below.
     *
     * Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved
     *
     * Permission is hereby granted, free of charge, to any person obtaining a copy
     * of this software and associated documentation files (the "Software"), to deal
     * in the Software without restriction, including without limitation the rights
     * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
     * copies of the Software, and to permit persons to whom the Software is
     * furnished to do so, subject to the following conditions:
     *
     * The above copyright notice and this permission notice shall be included in
     * all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
     * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
     * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
     * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
     * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
     * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
     * THE SOFTWARE.
     *
     */
    var scrypt = function (password, salt, N, r, p, L) {
        var MAX_VALUE = 2147483647;

        function kdf(password, salt, N, r, p, L) {
            if (N === 0 || (N & (N - 1)) !== 0) throw Error("N must be > 0 and a power of 2");

            if (N > MAX_VALUE / 128 / r) throw Error("Parameter N is too large");
            if (r > MAX_VALUE / 128 / p) throw Error("Parameter r is too large");

            var XY = []; //new Array(256 * r);
            var V  = []; //new Array(128 * r * N);

            var B = Verso.Encoding.wordsToBytes(sjcl.misc.pbkdf2(password, Verso.Encoding.bytesToWords(salt), 1, p * 128 * r * 8));

            for(var i = 0; i < p; i++) {
                smix(B, i * 128 * r, r, N, V, XY);
            }

            var DK = Verso.Encoding.wordsToBytes(sjcl.misc.pbkdf2(password, Verso.Encoding.bytesToWords(B), 1, L));

            return DK;
        }

        function smix(B, Bi, r, N, V, XY) {
            var Xi = 0;
            var Yi = 128 * r;
            var i;

            arraycopy(B, Bi, XY, Xi, Yi);

            for (i = 0; i < N; i++) {
                arraycopy(XY, Xi, V, i * Yi, Yi);
                blockmix_salsa8(XY, Xi, Yi, r);
            }

            for (i = 0; i < N; i++) {
                var j = integerify(XY, Xi, r) & (N - 1);
                blockxor(V, j * Yi, XY, Xi, Yi);
                blockmix_salsa8(XY, Xi, Yi, r);
            }

            arraycopy(XY, Xi, B, Bi, Yi);
        }

        function blockmix_salsa8(BY, Bi, Yi, r) {
            var X = [];
            var i;

            arraycopy32(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

            for (i = 0; i < 2 * r; i++) {
                blockxor(BY, i * 64, X, 0, 64);
                salsa20_8(X);
                arraycopy32(X, 0, BY, Yi + (i * 64), 64);
            }

            for (i = 0; i < r; i++) {
                arraycopy32(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64);
            }

            for (i = 0; i < r; i++) {
                arraycopy32(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
            }
        }

        function R(a, b) {
            return (a << b) | (a >>> (32 - b));
        }

        function salsa20_8(B) {
            var B32 = new Array(32);
            var x   = new Array(32);
            var i;

            for (i = 0; i < 16; i++) {
                B32[i]  = (B[i * 4 + 0] & 0xff) << 0;
                B32[i] |= (B[i * 4 + 1] & 0xff) << 8;
                B32[i] |= (B[i * 4 + 2] & 0xff) << 16;
                B32[i] |= (B[i * 4 + 3] & 0xff) << 24;
            }

            arraycopy(B32, 0, x, 0, 16);

            for (i = 8; i > 0; i -= 2) {
                x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
                x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
                x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
                x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
                x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
                x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
                x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
                x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
                x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
                x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
                x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
                x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
                x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
                x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
                x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
                x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
            }

            for (i = 0; i < 16; ++i) B32[i] = x[i] + B32[i];

            for (i = 0; i < 16; i++) {
                var bi = i * 4;
                B[bi + 0] = (B32[i] >> 0  & 0xff);
                B[bi + 1] = (B32[i] >> 8  & 0xff);
                B[bi + 2] = (B32[i] >> 16 & 0xff);
                B[bi + 3] = (B32[i] >> 24 & 0xff);
            }
        }

        function blockxor(S, Si, D, Di, len) {
            var i = len>>6;
            while (i--) {
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
            }
        }

        function integerify(B, bi, r) {
            var n;

            bi += (2 * r - 1) * 64;

            n  = (B[bi + 0] & 0xff) << 0;
            n |= (B[bi + 1] & 0xff) << 8;
            n |= (B[bi + 2] & 0xff) << 16;
            n |= (B[bi + 3] & 0xff) << 24;

            return n;
        }

        function arraycopy(src, srcPos, dest, destPos, length) {
             while (length-- ){
                 dest[destPos++] = src[srcPos++];
             }
        }

        function arraycopy32(src, srcPos, dest, destPos, length) {
            var i = length>>5;
            while(i--) {
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];

                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];

                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];

                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
            }
        }

        return kdf(password, salt, N, r, p, L);
    };

    /**
     * Hashes the input byte array with SHA256
     *
     * @memberOf Verso.Cryptography
     * @param {ByteArray} ba The data to hash
     */
    var SHA256 = function (ba) {
        return Verso.Encoding.wordArrayToBytes(CryptoJS.SHA256(Verso.Encoding.bytesToWordArray(ba)));
    };

    /**
     * Hashes the input byte array with SHA256 of SHA256
     *
     * @memberOf Verso.Cryptography
     * @param {ByteArray} ba The data to hash
     */
    var SHASHA256 = function (ba) {
        return Verso.Encoding.wordArrayToBytes(CryptoJS.SHA256(CryptoJS.SHA256(Verso.Encoding.bytesToWordArray(ba))));
    };

    /**
     * Hashes the input byte array with SHA256 of SHA256 of SHA256
     *
     * @memberOf Verso.Cryptography
     * @param {ByteArray} ba The data to hash
     */
    var SHASHASHA256 = function (ba) {
        return Verso.Encoding.wordArrayToBytes(CryptoJS.SHA256(CryptoJS.SHA256(CryptoJS.SHA256(Verso.Encoding.bytesToWordArray(ba)))));
    };

    /**
     * Hashes the input byte array with RIPEMD160
     *
     * @memberOf Verso.Cryptography
     * @param {ByteArray} ba The data to hash
     */
    var RIPEMD160 = function (ba) {
        return Verso.Encoding.wordArrayToBytes(CryptoJS.RIPEMD160(Verso.Encoding.bytesToWordArray(ba)));
    };

    /**
     * Hashes the input byte array with RIPEMD160 of SHA256
     *
     * @memberOf Verso.Cryptography
     * @param {ByteArray} ba The data to hash
     */
    var SHA256RIPEMD160 = function (ba) {
        return RIPEMD160(SHA256(ba));
    };

    /**
     * Hashes the input byte array with HMAC-SHA512
     *
     * @memberOf Verso.Cryptography
     * @param {ByteArray} ba  The data to hash
     * @param {ByteArray} key The key
     * @return {ByteArray}    The hash
    */
    var HMACSHA512 = function (ba, key) {
        return Verso.Encoding.wordArrayToBytes(CryptoJS.HmacSHA512(Verso.Encoding.bytesToWordArray(ba), Verso.Encoding.bytesToWordArray(key)));
    };

    /**
     * Encrypts the plaintext with AES-CTR-NoPadding. If the IV is not specified, it is concatenated in front of the resulting ciphertext.
     *
     * @memberOf Verso.Cryptography
     * @param  {ByteArray} plaintext The plaintext
     * @param  {ByteArray} key       The key
     * @param  {ByteArray} [iv]      The IV
     * @return {ByteArray}           The ciphertext
     */
    var aesEncrypt = function (plaintext, key, iv) {
        var ivPredefined = (iv !== undefined);

        if (!ivPredefined) {
            iv = Verso.Cryptography.randomBytes(128/8, 0);
        }

        var cipherParams =
        {
            iv: Verso.Encoding.bytesToWordArray(iv),
            mode: CryptoJS.mode.CTR,
            padding: CryptoJS.pad.NoPadding
        };

        var ciphertext = Verso.Encoding.wordArrayToBytes(CryptoJS.AES.encrypt(Verso.Encoding.bytesToWordArray(plaintext), Verso.Encoding.bytesToWordArray(key), cipherParams).ciphertext);

        if (ivPredefined)
            return ciphertext;
        else
            return iv.concat(ciphertext);
    };

    /**
     * Decrypts the ciphertext with AES-CTR-NoPadding. If the IV is not specified, assumes that it is concatenated in front of the ciphertext.
     *
     * @memberOf Verso.Cryptography
     * @param  {ByteArray} ciphertext The ciphertext
     * @param  {ByteArray} key        The key
     * @param  {ByteArray} [iv]       The IV
     * @return {ByteArray}            The plaintext
     */
    var aesDecrypt = function (ciphertext, key, iv) {
        if (iv === undefined) {
            iv = ciphertext.slice(0, 128 / 8);
            ciphertext = ciphertext.slice(128 / 8);
        }

        var cipherParams =
        {
            iv: Verso.Encoding.bytesToWordArray(iv),
            mode: CryptoJS.mode.CTR,
            padding: CryptoJS.pad.NoPadding
        };

        return Verso.Encoding.wordArrayToBytes(CryptoJS.AES.decrypt({ciphertext: Verso.Encoding.bytesToWordArray(ciphertext)}, Verso.Encoding.bytesToWordArray(key), cipherParams));
    };

    /**
     * Encrypts the plaintext with RSA-2048
     *
     * @memberOf Verso.Cryptography
     * @param  {ByteArray} plaintext The plaintext
     * @param  {Hex}       modulus   The modulus
     * @param  {Hex}       exponent  The public exponent
     * @return {ByteArray}           The ciphertext
     */
    var rsaEncrypt = function (plaintext, modulus, exponent) {
        var rsa = new RSAKey();
        rsa.setPublic(modulus, exponent);

        var res = rsa.encrypt(plaintext);
        if (res)
            return Verso.Encoding.wordArrayToBytes(CryptoJS.enc.Hex.parse(res));
        else
            return null;
    };

    /**
     * Shares the secret based on Shamir's Secret Sharing algorithm
     *
     * @memberOf Verso.Cryptography
     * @param  {ByteArray} secret     The secret to share
     * @param  {Integer}   n          The number of shares to generate
     * @param  {Integer}   k          The minimum number of shares for combination
     * @param  {Integer}   [paranoia] The desired level of paranoia
     * @return {ByteArray}            The secret shares
     */
    var secretShare = function (secret, n, k, paranoia) {
        if (paranoia === undefined)
            paranoia = 6;

        secrets.setRNG(function (bits) {
            var b = randomBytes(bits / 8, paranoia);

            var result = "";
            for (var i = 0; i < b.length; i++) {
                var tmp = b[i].toString(2);
                while (tmp.length < 8) tmp = "0" + tmp;
                result += tmp;
            }

            return result;
        });

        var shares = secrets.share(Verso.Encoding.bytesToBase16(secret), n, k);
        shares = shares.map(function (s) { return Verso.Encoding.base16ToBytes(s.slice(1)); });

        return shares;
    };

    /**
     * Combines the secret shares based on Shamir's Secret Sharing algorithm
     *
     * @memberOf Verso.Cryptography
     * @param  {Array.ByteArray} shares The secret shares
     * @return {ByteArray}              The secret
     */
    var secretCombine = function (shares) {
        shares = shares.map(function (s) { return "8".concat(Verso.Encoding.bytesToBase16(s)); });

        return Verso.Encoding.base16ToBytes(secrets.combine(shares));
    };

    return {
        randomBytes: randomBytes,
        addPureEntropy: addPureEntropy,
        isRngReady: isRngReady,
        PBKDF2: PBKDF2,
        scrypt: scrypt,
        SHA256: SHA256,
        SHASHA256: SHASHA256,
        SHASHASHA256: SHASHASHA256,
        RIPEMD160: RIPEMD160,
        SHA256RIPEMD160: SHA256RIPEMD160,
        HMACSHA512: HMACSHA512,
        aesEncrypt: aesEncrypt,
        aesDecrypt: aesDecrypt,
        rsaEncrypt: rsaEncrypt,
        secretShare: secretShare,
        secretCombine: secretCombine
    };
})();