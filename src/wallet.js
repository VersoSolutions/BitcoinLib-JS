/**
 * Bitcoin wallet
 *
 * @constructor
 * @param  {Endpoint} ep                 Endpoint or list of enpoints used by the wallet
 * @param  {Function} [changeMethod]     Function selecting the change address, main address by default
 * @param  {Number}   [minConfirmations] Minimum number of confirmations for balance (2 by default)
 * @param  {Number}   [defaultFee]       Default fee amount in Satoshis (50000 by default)
 * @param  {Object}   [provider]         Object providing Bitcoin services (Verso.Bitcoin.Providers.Blockchain by default)
 */
Verso.Bitcoin.Wallet = function (ep, changeMethod, minConfirmations, defaultFee, provider) {
    var bitcoin = Verso.Bitcoin,
        encoding = Verso.Encoding;

    var that = this;
    var endpoints = [];
    var transactions = [];
    var balance = 0;
    var balancePending = 0;
    var onTx = [];
    var onBalance = [];
    var fetchTime;
    var unspents;

    if (changeMethod === undefined || changeMethod === null)
        changeMethod = function (e) { return that.getEndpoint(); };
    if (minConfirmations === undefined || minConfirmations < 1)
        minConfirmations = 2;
    if (defaultFee === undefined)
        defaultFee = 10000; // TODO: Make this dependent on transaction size
    if (provider === undefined)
        provider = bitcoin.Providers.Blockchain;

    /** Adds enpoints to the wallet */
    this.addEndpoints = function (e) {
        e = bitcoin.Endpoint.toList(e);

        for (var i = 0; i < e.length; i++) {
            var exists = false;

            for (var j = 0; j < endpoints.length; j++) {
                if (endpoints[j].sameAs(e[i])) {
                    if (!e[i].isWatchOnly())
                        endpoints[j] = e[i];
                    exists = true;
                    break;
                }
            }

            if (!exists) {
                endpoints.push(e[i]);
            }
        }
    };

    this.addEndpoints(ep);

    /** Returns the main endpoint */
    this.getEndpoint = function () {
        return endpoints[0];
    };

    /** Returns a copy of the wallet endpoints */
    this.getEndpoints = function () {
        return endpoints.slice(0);
    };

    /** Returns the next endpoint used for change and adds it to the wallet endpoints */
    this.nextChangeEndpoint = function () {
        var change = changeMethod(that);
        that.addEndpoints(change);

        return change;
    };

    /** Sets the change method */
    this.setChangeMethod = function (method) {
        changeMethod = method;
    };

    /** Returns the Bitcoin service provider */
    this.getProvider = function () {
        return provider;
    };

    /** Makes all endpoints watch-only */
    this.makeWatchOnly = function () {
        endpoints = endpoints.map( function(ep) { return ep.asWatchOnly(); });
    };

    /** Returns a spendable copy of the wallet */
    this.makeSpendable = function (eps) {
        eps = bitcoin.Endpoint.toList(eps);

        endpoints = endpoints.map(function (ep) {
            e = eps.filter(function (ee) { return ee.sameAs(ep); });

            if (e.length > 0)
                return e[0];
            return ep;
        });
    };

    /** Adds transactions to the wallet */
    this.addTransactions = function (txs, all) {
        if(!Array.isArray(txs))
            txs = [txs];

        var newTx = [];
        var newConfirm = false;
        var i;

        for (i = 0; i < txs.length; i++) {
            if (!txs[i].hasEndpoints(that.getEndpoints())) {
                continue;
            }

            var exists = transactions.some(function (t) { return t.sameAs(txs[i]); });

            if (!exists) {
                transactions.push(txs[i]);
                newTx.push(txs[i]);
            } else if(txs[i].getBlock().getHeight() !== undefined) {
                var tx = transactions.filter(function (t) { return t.sameAs(txs[i]); })[0];

                if (tx.getBlock().getHeight() === undefined) {
                    tx.setBlock(txs[i].getBlock());
                    newConfirm = true;
                }
            }
        }

        if (newTx.length > 0 || newConfirm) {
            for (i = 0; i < onTx.length; i++) {
                try {
                    onTx[i](that, newTx);
                } catch (e) {}
            }
        }

        if (all)
            fetched = true;
    };

    /** Returns a copy of the wallet transactions */
    this.getTransactions = function () {
        return transactions.slice(0);
    };

    /** Clears transactions kept in the wallet */
    this.clearTransactions = function () {
        transactions = [];
    };

    /** Adds a transaction event handler */
    this.addTransactionEventHandler = function (event) {
        onTx.push(event);
    };

    /** Removes a transaction event handler */
    this.removeTransactionEventHandler = function (event) {
        var i = onTx.indexOf(event);

        if (i > -1)
            onTx.splice(i, 1);
    };

    provider.subscribeBlock(function (block) {
        // Check whether previously unconfirmed txs are now in blockchain
        if (transactions.some(function (tx) { return tx.getBlock().getHeight() === undefined; }))
            that.fetch();
    });

    this.setBalance = function (bal, pending) {
        if (pending === undefined)
            pending = balancePending;

        if (bal != balance || balancePending != pending) {
            balance = bal;
            balancePending = pending;

            for (var i = 0; i < onBalance.length; i++) {
                try {
                    onBalance[i](that, balance, balancePending);
                } catch (e) { }
            }
        }
    };

    /** Returns the confirmed wallet balance */
    this.getBalance = function () {
        return balance;
    };

    /** Returns the unconfirmed wallet balance */
    this.getBalancePending = function () {
        return balancePending;
    };

    /** Adds a balance event handler */
    this.addBalanceEventHandler = function (event) {
        onBalance.push(event);
    };

    /** Removes a balance event handler */
    this.removeBalanceEventHandler = function (event) {
        var i = onBalance.indexOf(event);

        if (i > -1)
            onBalance.splice(i, 1);
    };

    /** Returns the minimum number of confirmations used to compute balance */
    this.getMinConfirmations = function () {
        return minConfirmations;
    };

    /** Returns the default fee */
    this.getDefaultFee = function () {
        return defaultFee;
    };

    /** Sets the default fee */
    this.setDefaultFee = function (fee) {
        defaultFee = fee;
    };

    /** Returns the time of the last fetch */
    this.getFetchTime = function () {
        return fetchTime;
    };

    /** Sets the time of last fetch */
    this.setFetchTime = function (time) {
        if(fetchTime === undefined || time > fetchTime)
            fetchTime = time;
    };

    /** Sets the usable unspents */
    this.setUnspents = function (u) {
        unspents = u;
    };

    /** Returns the fee in satoshis for the next payment */
    this.getCurrentFee = function () {
        return Math.min(100000, Math.ceil(unspents.length/4) * this.getDefaultFee());
    };
};

/**
 * Fetches all wallet information (e.g. transactions, balance, latest block, unspent)
 *
 * @param  {Function} [onResult]  Callback for transactions, balance, pending balance and unspent outputs
 * @param  {Function} [onBalance] Callback for balance, pending balance and unspent outputs
 * @param  {Function} [onError]   Callback in case of error
 */
Verso.Bitcoin.Wallet.prototype.fetch = function (onResult, onError) {
    var that = this;

    this.getProvider().fetchTx(
        that.getEndpoints(),
        function (txs) {
            that.addTransactions(txs, true);

            that.getProvider().fetchUnspent(that.getEndpoints(), function (ins) {
                var bal;
                var pending;

                var usable = ins.filter(function (i) {
                    var conf = i.confirmations >= that.getMinConfirmations();

                    var tx = that.getTransactions().filter(function (t) { return t.sameAs(i.getHash()); });

                    // Allow using unconfirmed inputs if they come from the wallet (e.g. change)
                    return conf || (tx.length == 1 && tx[0].getIns().every(function (ii) { return that.getEndpoints().some(function (ep) { return ep.sameAs(ii.getEndpoint()); }); }));
                });

                bal = usable.reduce(function (i, j) { return i + j.getAmount(); }, 0);
                pending = ins.reduce(function (i, j) { return i + j.getAmount(); }, 0) - bal;

                that.setBalance(bal, pending);
                that.setUnspents(usable);

                that.setFetchTime(new Date());

                try
                {
                    if (onResult)
                        onResult(txs, bal, pending, usable);
                }
                catch (e) {
                }
            },
            onError);
        },
        onError
    );
};

/**
 * Sends Bitcoins from the wallet to a given address
 *
 * @param  {Endpoint|String|ByteArray} to          The destination endpoint (can be the public hash in Base58Check or byte array format)
 * @param  {Number}                    amount      The amount to send (in satoshis)
 * @param  {Number}                    [fee]       The fee for the transaction
 * @param  {Function}                  [onSuccess] Callback in case of success
 * @param  {Function}                  [onError]   Callback in case of error
 */
Verso.Bitcoin.Wallet.prototype.send = function (to, amount, fee, onSuccess, onError) {
    var encoding = Verso.Encoding;
    var bitcoin = Verso.Bitcoin;

    if (amount === undefined || amount <= 0)
        throw new Verso.Error("Invalid amount!");
    if (fee === undefined)
        fee = this.getDefaultFee();
    if (!(to instanceof bitcoin.Endpoint))
        to = new bitcoin.Endpoint(to);

    var that = this;
    amount = Math.round(amount); // in satoshis
    fee = Math.round(fee);

    this.fetch(
        function (txs, balance, pending, ins) {
            try {
                // Select inputs
                ins = ins.filter(function (i) { return !i.getEndpoint().isWatchOnly(); })
                         .sort(function (a, b) { // Sort by decreasing age
                            var blocka = txs.filter(function (t) {
                                return t.sameAs(a.getHash());
                            })[0].getBlock().getHeight();

                            var blockb = txs.filter(function (t) {
                                return t.sameAs(b.getHash());
                            })[0].getBlock().getHeight();

                            if (blocka === undefined && blockb === undefined) {
                                return 0;
                            } else if (blocka === undefined && blockb !== undefined) {
                                return 1;
                            } else if (blockb === undefined && blocka !== undefined) {
                                return -1;
                            } else {
                                return blocka - blockb;
                            }
                         })
                         .reduce(function (prev, curr) { // Select minimum number of inputs
                            if (prev.reduce(function (i, j) { return i + j.getAmount(); }, 0) < amount + fee) {
                                prev.push(curr);
                            }
                            return prev;
                         }, []);

                balance = ins.reduce(function (i, j) { return i + j.getAmount(); }, 0); // Amount spent

                var change = balance - (amount + fee);

                if (change >= 0) {
                    var outs = [new bitcoin.TxOut(to, amount)];

                    if (change > 0)
                        outs.push(new bitcoin.TxOut(that.nextChangeEndpoint(), change));

                    that.getProvider().send(new Verso.Bitcoin.Tx(ins, outs), onSuccess, onError);
                }
                else if (onError) {
                    onError(new Verso.BalanceError("Insufficient balance!"));
                }
            }
            catch (err) {
                if (onError)
                    onError(new Verso.Error("Transaction interrupted!"));
            }
        },
        onError
    );
};

/**
* Redeem an Endpoint
*
* @param  {Endpoint|String|ByteArray} to          The destination endpoint
* @param  {Number}                    [fee]       The fee for the transaction
* @param  {Function}                  [onSuccess] Callback in case of success
* @param  {Function}                  [onError]   Callback in case of error
*/
Verso.Bitcoin.Wallet.prototype.redeem = function (source, fee, onSuccess, onError) {
    var that = this;

    this.getProvider().fetchUnspent(source, function (ins) {
        try {
            var balance = ins.reduce(function (i, j) { return i + j.getAmount(); }, 0);

            if(fee === undefined)
                fee = that.getDefaultFee();

            if (balance > 0) {
                var outs = [new bitcoin.TxOut(that.getEndpoint(), balance - fee)];

                that.getProvider().send(new Verso.Bitcoin.Tx(ins, outs), onSuccess, onError);
            }
            else if (onError) {
                onError(new Verso.BalanceError("No funds to redeem!"));
            }
        }
        catch (err) {
            if (onError)
                onError(new Verso.Error("Transaction interrupted!"));
        }
    },
    onError
    );
};