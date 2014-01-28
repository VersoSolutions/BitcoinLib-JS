/** Bitcoin ECDSA curve */
Verso.Bitcoin.Curve = (function () { return getSECCurveByName("secp256k1"); })();

/**
 * Bitcoin endpoint (key pair)
 *
 * @constructor
 * @param {ByteArray|String} [data] A private key (raw or WIF) or a public key hash (raw or Base58Check)
 */
Verso.Bitcoin.Endpoint = function (data) {
    var encoding = Verso.Encoding,
        curve = Verso.Bitcoin.Curve,
        cryptography = Verso.Cryptography,
        bitcoin = Verso.Bitcoin;

    var that = this;
    var watchOnly;
    var privateKey;
    var privateCheck;
    var pt;
    var pub;
    var pubc;
    var pubHash;
    var address;

    var genKey = function (bigint) {
        var key = encoding.bytesUnsignedToBigInteger(cryptography.randomBytes(32, 6))
            .mod(curve.getN().subtract(BigInteger.ONE))
            .add(BigInteger.ONE);

        if (bigint)
            return key;

        return encoding.bigIntegerToBytesUnsigned(key, 32);
    };

    var derivePublic = function () {
        if (watchOnly || (typeof pt != "undefined" && typeof pub != "undefined" && typeof pubc != "undefined"))
            return;

        // Compute public key
        pt = curve.getG().multiply(encoding.bytesUnsignedToBigInteger(privateKey));
        pt = {
            x: pt.getX().toBigInteger(),
            y: pt.getY().toBigInteger()
        };

        // Convert to DER format
        pub = encoding.bigIntegerToBytesUnsigned(pt.x, 32);
        pub.unshift(0x04);
        pub = pub.concat(encoding.bigIntegerToBytesUnsigned(pt.y, 32));

        // Compressed form
        pubc = encoding.bigIntegerToBytesUnsigned(pt.x, 32);
        if (pt.y.isEven())
            pubc.unshift(0x02);
        else
            pubc.unshift(0x03);

        // Compute address hash and string address
        pubHash = cryptography.SHA256RIPEMD160(pub);
        address = encoding.bytesToBase58(encoding.bytesToCheck(pubHash, 0x00));
    };

    if (typeof data == "undefined") {
        data = genKey();
    }
    else if (typeof data == "string") {
        data = encoding.base58ToBytes(data);
    }
    else if (data instanceof Verso.Bitcoin.Endpoint) {
        if (data.isWatchOnly())
            data = data.getPublicHash();
        else
            data = data.getPrivate();
    }

    if (Array.isArray(data) && data.length == 20) { // pubHash
        pubHash = data;
        address = encoding.bytesToBase58(encoding.bytesToCheck(data, 0x00));
        watchOnly = true;
    }
    else if (Array.isArray(data) && data.length == 25) { // address
        pubHash = encoding.checkToBytes(data, 0x00);
        address = encoding.bytesToBase58(data);
        watchOnly = true;
    }
    else {
        if (Array.isArray(data) && data.length == 32) { // private exponent
            privateKey = data;
            privateCheck = encoding.bytesToBase58(encoding.bytesToCheck(privateKey, 0x80));
        }
        else if (Array.isArray(data) && data.length == 37) { // wif
            privateKey = encoding.checkToBytes(data, 0x80);
            privateCheck = encoding.bytesToBase58(data);
        }
        else throw new Verso.Error("Invalid argument");

        watchOnly = false;

        /** Returns the private key */
        this.getPrivate = function () { return privateKey; };
        /** Returns the WIF private key */
        this.getPrivateCheck = function () { return privateCheck; };
        /** Returns the public point of the EC key */
        this.getPublicPoint = function () { derivePublic(); return pt; };
        /** Returns the DER-encoded public EC key */
        this.getPublic = function (compressed) {
            derivePublic();
            if (compressed) return pubc;
            else return pub;
        };

        /** Signs a hash using ECDSA algorithm and encodes it in DER */
        this.sign = function (hash) {
            var d = encoding.bytesUnsignedToBigInteger(that.getPrivate());
            var n = curve.getN();
            var e = encoding.bytesUnsignedToBigInteger(hash);
            var k, r;

            do {
                k = genKey(true);
                r = curve.getG().multiply(k).getX().toBigInteger().mod(n);
            } while (r.compareTo(BigInteger.ZERO) <= 0);

            var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

            // DER encoding
            var rBa = encoding.bigIntegerToBytesSigned(r);
            var sBa = encoding.bigIntegerToBytesSigned(s);

            var sequence = [];
            sequence.push(0x02);
            sequence.push(rBa.length);
            sequence = sequence.concat(rBa);

            sequence.push(0x02);
            sequence.push(sBa.length);
            sequence = sequence.concat(sBa);

            sequence.unshift(sequence.length);
            sequence.unshift(0x30);

            return sequence;
        };
    }

    /** Returns the hash of the public key */
    this.getPublicHash = function () { derivePublic(); return pubHash; };
    /** Returns the Bitcoin address in Base58Check string format */
    this.getAddress = function () { derivePublic(); return address; };
    /** Returns a new watch-only version of the endpoint */
    this.asWatchOnly = function () { derivePublic(); if (!watchOnly) return new Verso.Bitcoin.Endpoint(address); return that; };
    /** Returns true if the endpoint is watch-only */
    this.isWatchOnly = function () { return watchOnly; };
    /** Compares two endpoints */
    this.sameAs = function (ep) {
        if (ep === null)
            return false;

        if (!(ep instanceof Verso.Bitcoin.Endpoint))
            ep = new Verso.Bitcoin.Endpoint(ep);

        if (watchOnly || ep.isWatchOnly()) {
            return that.getAddress() == ep.getAddress();
        }

        var other = ep.getPrivate();
        for (var i = 0; i < privateKey.length; i++) if (privateKey[i] !== other[i]) return false;
        return true;
    };
};

/**
 * Returns true if the data is a bitcoin address
 * 
 * @param  {String|ByteArray} data   The data to test
 * @return {Boolean}                 Returns true if data is a bitcoin address   
 */
Verso.Bitcoin.isAddress = function (data) {
    var encoding = Verso.Encoding;

    if (typeof data == "string") {
        data = encoding.base58ToBytes(data);
    }

    if (!Array.isArray(data) || data.length != 25)
        return false;

    try {
        encoding.checkToBytes(data, 0x00);
        return true;
    }
    catch (e) {
        return false;
    }
};

/**
 * Processes the list of loosely-typed endpoints (string addresses, endpoints, etc.) into an array of corresponding Endpoint instances
 * 
 * @param  {Endpoint|String|ByteArray} endpoints The list of endpoints
 * @return {Array.Endpoint}                      The processed array of endpoints
 */
Verso.Bitcoin.Endpoint.toList = function (endpoints) {
    if (typeof endpoints == "undefined")
        return [];

    if (!Array.isArray(endpoints))
        endpoints = [endpoints];

    for (var i = 0; i < endpoints.length; i++) {
        if (!(endpoints[i] instanceof Verso.Bitcoin.Endpoint))
            endpoints[i] = new Verso.Bitcoin.Endpoint(endpoints[i]);
    }

    return endpoints;
};

/**
 * Bitcoin extended endpoint as defined in BIP 0032
 *
 * @constructor
 * @extends {Endpoint}
 * @param   {ByteArray|String} data      The private key (raw or WIF)
 * @param   {ByteArray}        chainCode The chain code
 */
Verso.Bitcoin.ExtendedEndpoint = function (data, chainCode) {
    Verso.Bitcoin.Endpoint.call(this, data);

    /** Returns the chain code of the extended endpoint */
    this.getChainCode = function () { return chainCode; };
};

Verso.Bitcoin.ExtendedEndpoint.prototype = Verso.Class.inherit(Verso.Bitcoin.Endpoint.prototype);

/**
 * Generates a child extended endpoint
 * 
 * @param  {Integer}          index The index of the child
 * @param  {Boolean)          pub   Boolean indicating whether public derivation should be used
 * @return {ExtendedEndpoint}       The child extended endpoint
 */
Verso.Bitcoin.ExtendedEndpoint.prototype.getChild = function (index, pub) {
    var encoding = Verso.Encoding,
        curve = Verso.Bitcoin.Curve,
        cryptography = Verso.Cryptography;

    if (typeof index == "undefined")
        index = 0;
    else if (index < 0)
        throw new Verso.Error("Index cannot be negative!");

    var IL, IR, newKey;
    index--;
    do {
        index++;

        if (index > 0x7FFFFFFF)
            throw new Verso.Error("Index is too large!");

        var hmacData = encoding.integerToBytesUnsigned(index, 4);
        if (pub) {
            hmacData[0] &= 0x7F;
            hmacData = this.getPublic(true).concat(hmacData);
        }
        else {
            hmacData[0] |= 0x80;
            hmacData = [0x00].concat(this.getPrivate()).concat(hmacData);
        }

        var I = cryptography.HMACSHA512(hmacData, this.getChainCode());
        IL = encoding.bytesUnsignedToBigInteger(I.slice(0, 32));
        IR = encoding.bytesUnsignedToBigInteger(I.slice(32));
        newKey = IL.add(encoding.bytesUnsignedToBigInteger(this.getPrivate())).mod(curve.getN());
    } while (IL.compareTo(curve.getN()) >= 0 || newKey.compareTo(BigInteger.ZERO) === 0);

    return new Verso.Bitcoin.ChildEndpoint(encoding.bigIntegerToBytesUnsigned(newKey, 32), encoding.bigIntegerToBytesUnsigned(IR, 32), this, index);
};

/**
 * Bitcoin master endpoint
 *
 * @constructor
 * @extends {Endpoint}
 * @param   {ByteArray|String} [seed]      The seed used for determinism
 */
Verso.Bitcoin.MasterEndpoint = function (seed) {
    var encoding = Verso.Encoding,
    curve = Verso.Bitcoin.Curve,
    cryptography = Verso.Cryptography;

    var endpoint;
    var chainCode;

    var derive = function (s) {
        var I = cryptography.HMACSHA512(s, encoding.utf8ToBytes("Bitcoin seed"));

        var key = I.slice(0, 32);
        var chainCode = I.slice(32);

        var bi = encoding.bytesUnsignedToBigInteger(key);
        if (bi.compareTo(curve.getN()) >= 0 || bi.compareTo(BigInteger.ZERO) === 0)
            return { valid: false };
        return { key: key, chainCode: chainCode, valid: true };
    };

    var derived;

    if (typeof seed == "undefined") {
        do {
            seed = cryptography.randomBytes(32, 6);
            derived = derive(seed);
        } while (!derived.valid);
    } else {
        derived = derive(seed);

        if (!derived.valid)
            throw new Verso.Error("Invalid seed!");
    }

    Verso.Bitcoin.ExtendedEndpoint.call(this, derived.key, derived.chainCode);

    /** Returns the seed of the master node */
    this.getSeed = function () { return seed.slice(0); };
    /** Returns the path of the extended endpoint */
    this.getPath = function () { return []; };
    /** Returns true if object is the seed */
    this.isMaster = function () { return true; };
};

Verso.Bitcoin.MasterEndpoint.prototype = Verso.Class.inherit(Verso.Bitcoin.ExtendedEndpoint.prototype);

/**
 * Bitcoin extended endpoint as defined in BIP 0032
 *
 * @constructor
 * @extends {Endpoint}
 * @param   {ByteArray|String} data      The private key (raw or WIF)
 * @param   {ByteArray}        chainCode The chain code
 * @param   {ExtendedEndpoint} parent    The parent endpoint
 * @param   {IntArray}         path      The node path
 */
Verso.Bitcoin.ChildEndpoint = function (data, chainCode, parent, index) {
    Verso.Bitcoin.ExtendedEndpoint.call(this, data, chainCode);
    
    var path = parent.getPath().concat([index]);

    /** Returns the parent node of the extended endpoint */
    this.getParent = function () { return parent; };
    /** Returns the path of the extended endpoint */
    this.getPath = function () { return path; };
    /** Returns true if object is the master node */
    this.isMaster = function () { return false; };
};

Verso.Bitcoin.ChildEndpoint.prototype = Verso.Class.inherit(Verso.Bitcoin.ExtendedEndpoint.prototype);