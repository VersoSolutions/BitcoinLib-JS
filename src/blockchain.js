/**
 * Wrapper for main services of Blockchain.info (in particular, unspent outputs, address transactions history, transaction broadcast)
 */
Verso.Bitcoin.Providers.Blockchain = (function () {
    var encoding = Verso.Encoding,
        bitcoin = Verso.Bitcoin,
        that = this;

    var latestBlock = new Verso.Bitcoin.Block(); // Keeps track of latest block (updated when adequate service is called)
    var onBlock;

    var setLatestBlock = function (block) {
        if (latestBlock.getHeight() === undefined || block.getHeight() > latestBlock.getHeight()) {
            latestBlock = block;

            if (onBlock) {
                try {
                    onBlock(latestBlock);
                } catch (err) {

                }
            }
        }
    };

    /** Returns the latest block */
    var getLatestBlock = function () {
        return latestBlock;
    };

    /** Subscribes a callback to a new-block event */
    var subscribeBlock = function (callback) { // TODO: allow for multiple callbacks
        onBlock = callback;
    };

    var fetch = function (url, onSuccess, onError, data, method) {
        jQuery.ajax({
            type: (method === undefined) ? "GET" : method,
            url: url,
            data: data,
            success: function (res) {
                if (onSuccess)
                    onSuccess(res);
            },
            error: function (xhr, opt, err) {
                if (onError)
                    onError(new Verso.ConnectionError("Error connecting the server!", xhr));
            }
        });
    };

    var foldEndpoints = function (ep) {
        var addr = "";
        for (var i = 0; i < ep.length; i++) {
            addr += ep[i].getAddress();
            if (i < ep.length - 1)
                addr += "|";
        }

        return addr;
    };

    /**
     * Fetches unspent outputs of a sent of endpoints
     *
     * @memberOf Verso.Providers.Blockchain
     * @param {Endpoint} ep        An endpoint or an array of endpoints
     * @param {Function} onUnspent Function called with unspent outputs in case of success
     * @param {Function} onError   Function called in case of error
     */
    var fetchUnspent = function (ep, onUnspent, onError) {
        ep = bitcoin.Endpoint.toList(ep);

        var addr = foldEndpoints(ep);

        var url = "https://blockchain.info/unspent";
        var data = { cors: true, active: addr };

        var parseUnspent = function (data) {
            var txs = data.unspent_outputs;

            var unspent = [];

            for (var i = 0; i < txs.length; i++) {
                var conf = parseInt(txs[i].confirmations);
                var script = encoding.base16ToBytes(txs[i].script);

                var hash = encoding.base16ToBytes(txs[i].tx_hash).reverse();
                var amount = parseInt(txs[i].value, 10);
                var index = txs[i].tx_output_n;
                var sequence = [0xFF, 0xFF, 0xFF, 0xFF];

                if (script.length == 25 && script[0] == 118 && script[1] == 169 && script[23] == 136 && script[24] == 172) { // accept only standard tx for the timing
                    var e = new bitcoin.Endpoint(script.slice(3, 23));

                    for (var j = 0; j < ep.length; j++) {
                        if (ep[j].sameAs(e)) {
                            e = ep[j];
                            break;
                        }
                    }

                    if (e !== null) {
                        var tin = new bitcoin.TxIn(e, amount, hash, index, script, sequence);
                        tin.confirmations = conf;

                        unspent.push(tin);
                    }
                }
            }

            return unspent;
        };

        fetch(url,
            function (data) {
                try {
                    if (onUnspent)
                        onUnspent(parseUnspent(data));
                }
                catch (e) {
                    if (onError)
                        onError(new Verso.ConnectionError("Cannot parse server data!"));
                }
            },
            function (error) {
                if (error.xhr.responseText === "No free outputs to spend") {
                    if (onUnspent)
                        onUnspent([]);
                } else {
                    if (onError)
                        onError(error);
                }
            }, data);
    };

    /**
     * Fetches transactions related to a set of endpoints
     *
     * @memberOf Verso.Providers.Blockchain
     * @param {Endpoint} ep        An endpoint or an array of endpoints
     * @param {Function} onSuccess Function called with parsed transactions in case of success
     * @param {Function} onError   Function called in case of error
     */
    var fetchTx = function (ep, onSuccess, onError) {
        var parseTx = function (txs) {
            var res = [];

            for (var i = 0; i < txs.length; i++) {
                var hash = encoding.base16ToBytes(txs[i].hash);// seems that it is already big endian      .reverse();
                var time = new Date(parseInt(txs[i].time) * 1000); // unix timestamp
                var idx = txs[i].tx_index;
                var block;
                var k, amount, endpoint;

                if (txs[i].block_height !== undefined) {
                    block = new bitcoin.Block(parseInt(txs[i].block_height));
                }
                else {
                    block = new bitcoin.Block();
                }

                var txin = [];
                for (k = 0; k < txs[i].inputs.length; k++) {
                    amount = parseInt(txs[i].inputs[k].prev_out.value, 10);
                    endpoint = new bitcoin.Endpoint(txs[i].inputs[k].prev_out.addr);

                    txin.push(new bitcoin.TxIn(endpoint, amount));
                }

                var txout = [];
                for (k = 0; k < txs[i].out.length; k++) {
                    amount = parseInt(txs[i].out[k].value, 10);
                    endpoint = new bitcoin.Endpoint(txs[i].out[k].addr);

                    txout.push(new bitcoin.TxOut(endpoint, amount));
                }

                res.push(new bitcoin.Tx(txin, txout, hash, block, time, idx));
            }

            return res;
        };

        var that = this;
        ep = bitcoin.Endpoint.toList(ep);

        var addr = foldEndpoints(ep);

        var url = "https://blockchain.info/multiaddr";
        var data = { cors: true, active: addr };

        fetch(url, function (data) {
            var parsed;

            try {
                setLatestBlock(new bitcoin.Block(data.info.latest_block.height));

                if (onSuccess)
                    onSuccess(parseTx(data.txs));
            }
            catch (e) {
                if (onError)
                    onError(new Verso.ConnectionError("Cannot parse server data!"));
            }
        }, onError, data);
    };

    /**
     * Fetches the latest block found
     *
     * @memberOf Verso.Providers.Blockchain
     * @param {Function} onSuccess Function called with the latest block in case of success
     * @param {Function} onError   Function called in case of error
     */
    var fetchLatestBlock = function (onSuccess, onError) {
        var url = "https://blockchain.info/q/getblockcount";
        var data = { cors: true };

        var onFetchSuccess = function (data) {
            try {
                setLatestBlock(new bitcoin.Block(data));

                if (onSuccess)
                    onSuccess(latestBlock);
            } catch (e) {
                if (onError)
                    onError(new Verso.ConnectionError("Cannot parse server data!"));
            }
        };

        fetch(url, onFetchSuccess, onError, data);
    };

    /**
     * Broadcasts a transaction through Blockchain.info
     *
     * @memberOf Verso.Providers.Blockchain
     * @param {Verso.Bitcoin.Transaction} tx Transaction to broadcast
     * @param {Function} onSuccess Function called with the latest block in case of success
     * @param {Function} onError   Function called in case of error
     */
    var send = function (tx, onSuccess, onError) {
        tx = encoding.bytesToBase16(tx.serialize());

        var url = 'https://blockchain.info/pushtx';
        var data = { cors: true, tx: tx };

        fetch(url, onSuccess, onError, data, "POST");
    };

    return {
        getLatestBlock: getLatestBlock,
        subscribeBlock: subscribeBlock,
        fetchUnspent: fetchUnspent,
        fetchTx: fetchTx,
        fetchLatestBlock: fetchLatestBlock,
        send: send
    };
})();