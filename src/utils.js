/**
 * Selects the necessary inputs for a new transaction of a given amount.
 *
 * @param {Array.Txs} inputs The known transactions
 * @param {Array.Ins} inputs The available inputs
 * @param {Number}    amount The amount to send
 * @param {Number}    [fee]  The fees (if undefined, assumes standard fees)
 */
Verso.Bitcoin.Utils.selectInputs = function (txs, ins, amount, fee) {
    if (amount <= 0) {
        throw new Verso.Error("Invalid amount");
    }

    var arbitraryFee = (fee !== undefined);
    if (!arbitraryFee) { fee = 0; }

    // Select inputs
    ins = ins.sort(function (a, b) { // Sort by decreasing age
                 var blocka, blockb;

                 var txa = txs.filter(function (t) {
                     return t.sameAs(a.getHash());
                 })[0];
                 if (txa !== undefined) {
                    blocka = txa.getBlock().getHeight();
                 } else {
                    blocka = 0;
                 }

                 var txb = txs.filter(function (t) {
                     return t.sameAs(b.getHash());
                 })[0];
                 if (txb !== undefined) {
                    blockb = txb.getBlock().getHeight();
                 } else {
                    blockb = 0;
                 }

                 if (blocka === undefined && blockb === undefined) {
                     return 0;
                 } else if (blocka === undefined && blockb !== undefined) {
                     return 1;
                 } else if (blockb === undefined && blocka !== undefined) {
                     return -1;
                 } else {
                     return blocka - blockb;
                 }
             });

    balance = 0;
    var i = 0, selectedIns = [];
    while (i < ins.length && balance < amount + fee) {
        balance += ins[i].getAmount();
        selectedIns.push(ins[i]);
        i++;

        if (!arbitraryFee) {
            fee = Math.ceil(i/4) * 10000;
        }
    }

    if (balance < amount + fee) {
        throw new Verso.BalanceError("Insufficient balance");
    }

    return selectedIns;
};
