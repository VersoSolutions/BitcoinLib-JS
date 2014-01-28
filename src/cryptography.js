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
     * @param  {Array}   ba Entropic byte array 
     */
    var addPureEntropy = function (ba) {
        entropy = entropy.concat(ba);
    };

    /**
     * Returns true if the RNG has enough entropy
     *
     * @memberOf Verso.Cryptography
     * @return {ByteArray}            Returns true if the RNG has enough entropy
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
        if (typeof paranoia == "undefined")
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
        var ivPredefined = (typeof iv !== "undefined");

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
        if (typeof paranoia == "undefined")
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
     * Combines the secret shares based on Samir's Secret Sharing algorithm
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