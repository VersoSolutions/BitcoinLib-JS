/**
 * Converts Satoshis to Bitcoins
 * 
 * @param  {Integer} index The number of Satoshis
 * @return {Number}        The number of Bitcoins
 */
Verso.Bitcoin.satToBtc = function (s) { return s / 1e8; };

/**
 * Converts Bitcoins to Satoshis
 * 
 * @param  {Number} index The number of Bitcoins
 * @return {Integer}      The number of Satoshis
 */
Verso.Bitcoin.btcToSat = function (b) { return Math.round(b * 1e8); };

/**
 * Bitcoin transaction input
 *
 * @constructor
 * @param {Endpoint}  endpoint   The input endpoint
 * @param {Integer}   amount     The input amount in Satoshis
 * @param {ByteArray} [hash]     The hash of the transaction used as input [big-endian]
 * @param {Integer}   [index]    The output index of the input
 * @param {ByteArray} [script]   The script [big-endian]
 * @param {ByteArray} [sequence] The sequence number [big-endian]
 */
Verso.Bitcoin.TxIn = function (endpoint, amount, hash, index, script, sequence) {
    if (!(endpoint instanceof Verso.Bitcoin.Endpoint))
        endpoint = new Verso.Bitcoin.Endpoint(endpoint);

    if (typeof hash == "undefined")
        hash = [];
    if (typeof index == "undefined")
        index = -1;
    if (typeof script == "undefined")
        script = [];
    if (typeof sequence == "undefined")
        sequence = [0xFF, 0xFF, 0xFF, 0xFF];

    /** Returns a copy of the transaction hash [big-endian] */
    this.getHash = function () { return hash.slice(0); };
    /** Returns the transaction input index */
    this.getIndex = function () { return index; };
    /** Returns the transaction input script [big-endian] */
    this.getScript = function () { return script.slice(0); };
    /** Returns the transaction sequence number [big-endian] */
    this.getSequence = function () { return sequence.slice(0); };
    /** Returns the transaction endpoint */
    this.getEndpoint = function () { return endpoint; };
    /** Returns the amount of the transaction input in Satoshis */
    this.getAmount = function () { return amount; };
    /** Sets a new script for the transaction input */
    this.setScript = function(newScript) {
        script = newScript;
    };
    /** Clones the transaction input */
    this.clone = function () {
        return new Verso.Bitcoin.TxIn(endpoint, amount, hash.slice(0), index, script.slice(0), sequence.slice(0));
    };
    /** Returns true if transaction input can be used to sign a transaction */
    this.canSign = function () {
        return !endpoint.isWatchOnly() && hash.length > 0 && index >= 0 && script.length > 0 && sequence.length > 0;
    };
};

/**
 * Bitcoin transaction output
 *
 * @constructor
 * @param {Endpoint}          endpoint The output endpoint
 * @param {ByteArray|Numeric} amount   The output amount
 * @param {ByteArray}         [script] The script, [DUP EQUALVERIFY publicHash HASH160 CHECKSIG] by default
 */
Verso.Bitcoin.TxOut = function (endpoint, amount, script) {
    if (!(endpoint instanceof Verso.Bitcoin.Endpoint))
        endpoint = new Verso.Bitcoin.Endpoint(endpoint);

    if (typeof script == "undefined") {
        var OP_DUP = 118;
        var OP_EQUALVERIFY = 136;
        var OP_HASH160 = 169;
        var OP_CHECKSIG = 172;

        var pub = endpoint.getPublicHash();

        script = [];
        script.push(OP_DUP);
        script.push(OP_HASH160);
        script.push(pub.length);
        script = script.concat(pub);
        script.push(OP_EQUALVERIFY);
        script.push(OP_CHECKSIG);
    }

    /** Returns the destination endpoint */
    this.getEndpoint = function () { return endpoint; };
    /** Returns the amount */
    this.getAmount = function () { return amount; };
    /** Returns the output script */
    this.getScript = function () { return script.slice(0); };
};

/**
 * Bitcoin transaction
 *
 * @constructor
 * @param {Array.TxIn}  ins       The inputs
 * @param {Array.TxOut} outs      The outputs
 * @param {ByteArray}   [hash]    The transaction hash
 * @param {Integer}     [block]   The block height in which transaction was first added
 * @param {Number}      [Date]    The time at which transaction was broadcasted
 */
Verso.Bitcoin.Tx = function (ins, outs, hash, block, time) {
    var encoding = Verso.Encoding,
        cryptography = Verso.Cryptography,
        bitcoin = Verso.Bitcoin;

    if (!Array.isArray(ins))
        ins = [ins];
    if (!Array.isArray(outs))
        outs = [outs];
    if (hash === undefined)
        hash = [];
    if (block === undefined)
        block = new bitcoin.Block();
    if (time === undefined)
        time = 0;

    var serialized = [];
    ins = ins.slice(0);
    outs = outs.slice(0);

    var fees = ins.reduce(function (prev, curr) { return prev + curr.getAmount(); }, 0) -
               outs.reduce(function (prev, curr) { return prev + curr.getAmount(); }, 0);

    var serializeTx = function (ins, outs) {
        var buffer = [],
            i;

        buffer = buffer.concat([0x01, 0x00, 0x00, 0x00]);

        buffer = buffer.concat(encoding.numToVarInt(ins.length));
        for (i = 0; i < ins.length; i++) {
            buffer = buffer.concat(ins[i].getHash().reverse());
            buffer = buffer.concat(encoding.wordsToBytes([parseInt(ins[i].getIndex())]).reverse());

            buffer = buffer.concat(encoding.numToVarInt(ins[i].getScript().length));
            buffer = buffer.concat(ins[i].getScript());
            buffer = buffer.concat(ins[i].getSequence().reverse());
        }

        buffer = buffer.concat(encoding.numToVarInt(outs.length));
        for (i = 0; i < outs.length; i++) {
            buffer = buffer.concat(encoding.integerToBytesUnsigned(outs[i].getAmount(), 8).reverse());

            buffer = buffer.concat(encoding.numToVarInt(outs[i].getScript().length));
            buffer = buffer.concat(outs[i].getScript());
        }

        buffer = buffer.concat([0x00, 0x00, 0x00, 0x00]);

        return buffer;
    };

    var inputScript = function (index) {
        var hashType = 1;

        var ins_ = [];
        for (var i = 0; i < ins.length; i++) {
            var input = ins[i].clone();

            if (i != index)
                input.setScript([]);

            ins_.push(input);
        }

        var buffer = serializeTx(ins_, outs);
        buffer = buffer.concat(encoding.wordsToBytes([parseInt(hashType)]).reverse());

        var hash = cryptography.SHASHA256(buffer);
        var sign = ins[index].getEndpoint().sign(hash);
        var pub = ins[index].getEndpoint().getPublic();

        var script = [];
        script.push(sign.length+1);
        script = script.concat(sign);
        script.push(0x01);
        script.push(pub.length);
        script = script.concat(pub);

        return script;
    };

    /** Returns the transaction inputs */
    this.getIns = function () { return ins.slice(0); };
    /** Returns the transaction outputs */
    this.getOuts = function () { return outs.slice(0); };
    /** Returns the block height in which transaction is first included */
    this.getBlock = function () { return block; };
    /** Sets the block height in which transaction is first included */
    this.setBlock = function (b) { block = b; };
    /** Returns the time at which transaction is broadcasted */
    this.getTime = function () { return time; };
    /** Sets the time at which transaction is broadcasted */
    this.setTime = function (t) { time = t; };
    /** Returns the transaction hash */
    this.getHash = function () { return hash.slice(0); };
    /** Returns the transaction fees */
    this.getFees = function () { return fees; };
    /** Returns true if endpoints are related to the transaction */
    this.hasEndpoints = function (ep) {
        for (var i = 0; i < ep.length; i++) {
            if (this.getIns().some(function (ti) { return ti.getEndpoint().sameAs(ep[i]); }) ||
               this.getOuts().some(function (to) { return to.getEndpoint().sameAs(ep[i]); }))
                return true;
        }

        return false;
    };
    /** Returns the serialized version of the transaction */
    this.serialize = function () {
        if (serialized.length > 0)
            return serialized;

        if (!ins.every(function (i) { return i.canSign(); }))
            throw new Verso.Error("Tx inputs cannot be signed!");

        var ins_ = [];

        for (var i = 0; i < ins.length; i++) {
            var in_ = ins[i].clone();
            in_.setScript(inputScript(i));
            ins_.push(in_);
        }

        serialized = serializeTx(ins_, outs);
        hash = cryptography.SHASHA256(serialized);
        return serialized;
    };
};

/**
  * Returns true if the transactions are the same (comparing the hash)
  *
  * @param  {Verso.Bitcoin.Tx} tx Other transaction
  * @return {Boolean}             The comparison result
  */
Verso.Bitcoin.Tx.prototype.sameAs = function (tx) {
    if (tx instanceof Verso.Bitcoin.Tx)
        tx = tx.getHash();
    if (Array.isArray(tx))
        tx = Verso.Encoding.bytesToBase16(tx);

    return Verso.Encoding.bytesToBase16(this.getHash()) === tx;
};

/**
 * Returns true if the transaction is confirmed
 * 
 * @param  {Block}   latestBlock        The latest block
 * @param  {Integer} [minConfirmations] The number of confirmations required
 * @return {Boolean}                    The confirmation status
 */
Verso.Bitcoin.Tx.prototype.isConfirmed = function (latestBlock, minConfirmations) {
    if (typeof minConfirmations == "undefined")
        minConfirmations = 1;

    return (this.getBlock().getHeight() > 0 && latestBlock.getHeight() - this.getBlock().getHeight() >=  minConfirmations - 1);
};

/**
 * Returns the transaction type
 *
 * @param  {Array.Endpoint} The list of wallet endpoints (used to identify change)
 * @return {Integer}        The transaction amount in Satoshis
 */
Verso.Bitcoin.Tx.prototype.getAmount = function (ep) {
    ep = Verso.Bitcoin.Endpoint.toList(ep);

    var amount = this.getOuts()
                       .filter(function (to) { return ep.some(function (e) { return e.sameAs(to.getEndpoint()); }); })
                       .reduce(function (prev, curr) { return prev + curr.getAmount(); }, 0) -
                 this.getIns()
                       .filter(function (ti) { return ep.some(function (e) { return e.sameAs(ti.getEndpoint()); }); })
                       .reduce(function (prev, curr) { return prev + curr.getAmount(); }, 0);

    var otherOut = this.getOuts().filter(function (to) { return !ep.some(function (e) { return e.sameAs(to.getEndpoint()); }); });

    if (amount < 0 && (otherOut.length > 0 || this.getOuts().length === 0)) {
        return amount + this.getFees();
    }
    else if (amount <= 0 && otherOut.length === 0 && this.getOuts().length > 0) {
        return -this.getOuts().reduce(function (prev, curr) { return prev + curr.getAmount(); }, 0);
    }
    
    return amount;
};

/**
 * Returns the main endpoint of the transaction (e.g. largest output for outgoing transactions, largest input for incoming transactions)
 *
 * @param  {Array.Endpoint} The list of wallet endpoints (used to identify change)
 * @return {Integer}        The main endpoint
 */
Verso.Bitcoin.Tx.prototype.getMainEndpoint = function (ep) {
    var amount = this.getOuts()
                   .filter(function (to) { return ep.some(function (e) { return e.sameAs(to.getEndpoint()); }); })
                   .reduce(function (prev, curr) { return prev + curr.getAmount(); }, 0) -
                 this.getIns()
                   .filter(function (ti) { return ep.some(function (e) { return e.sameAs(ti.getEndpoint()); }); })
                   .reduce(function (prev, curr) { return prev + curr.getAmount(); }, 0);

    var otherOut = this.getOuts().filter(function (to) { return !ep.some(function (e) { return e.sameAs(to.getEndpoint()); }); });

    if (amount < 0 && otherOut.length > 0) {
        return otherOut.sort(function (a, b) { return b.getAmount() - a.getAmount(); })[0].getEndpoint();
    }
    else if (amount <= 0 && otherOut.length === 0 && this.getOuts().length > 0) {
        return this.getOuts().sort(function (a, b) { return b.getAmount() - a.getAmount(); })[0].getEndpoint();
    }
    else if (amount > 0) {
        return this.getIns()
                        .filter(function (ti) { return !ep.some(function (e) { return e.sameAs(ti.getEndpoint()); }); })
                        .sort(function (a, b) { return b.getAmount() - a.getAmount(); })[0]
                        .getEndpoint();
    }
    
    return false;
};

/**
 * Bitcoin block
 * 
 * @param {Integer} height The height of the block
 */
Verso.Bitcoin.Block = function (height) {
    if (typeof height === "undefined")
        height = 0;

    this.getHeight = function () { return height; };
};
