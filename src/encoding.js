/**
 * Main encoding tools
 */
Verso.Encoding = (function () {
    var Base58Table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var Base94Table = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

    var bigIntegerToBytesUnsigned = function (bi, len) {
        var ba = bi.abs().toByteArray();

        if (ba.length > 1 && ba[0] === 0) {
            ba = ba.slice(1);
        }

        if (ba.length) {
            ba = ba.map(function (v) { return (v < 0) ? v + 256 : v; });
        }
        else {
            ba = [0];
        }

        if (len !== undefined) {
            if (len < ba.length) {
                ba = ba.slice(ba.length - len);
            } else while (len > ba.length) {
                ba.unshift(0);
            }
        }

        return ba;
    };

    var bytesUnsignedToBigInteger = function (ba) {
        if (!ba.length) {
            return new BigInteger(0x00);
        } else if (ba[0] & 0x80) {
            return new BigInteger([0].concat(ba));
        } else {
            return new BigInteger(ba);
        }
    };

    var bigIntegerToBytesSigned = function (bi) {
        var val = bigIntegerToBytesUnsigned(bi.abs());
        var neg = bi.compareTo(BigInteger.ZERO) < 0;

        if (neg) {
            if (val[0] & 0x80) {
                val.unshift(0x80);
            } else {
                val[0] |= 0x80;
            }
        } else {
            if (val[0] & 0x80) {
                val.unshift(0x00);
            }
        }

        return val;
    };

    var bytesSignedToBigInteger = function (ba) {
        if (ba[0] & 0x80) {
            ba[0] &= 0x7f;
            return bytesUnsignedToBigInteger(ba).negate();
        } else {
            return bytesUnsignedToBigInteger(ba);
        }
    };

    var integerToBytesUnsigned = function (i, len) {
        return bigIntegerToBytesUnsigned(new BigInteger('' + i, 10), len); // TODO: implement properly
    };

    var stringToBytes = function (s, table) {
        var bi = BigInteger.ZERO;
        var n = BigInteger.ONE;
        var base = nbv(table.length);
        var zeros = 0;

        for (var i = 0; i < s.length; i++) {
            var c = s[s.length - i - 1];
            var k = nbv(table.indexOf(c));

            bi = bi.add(n.multiply(k));
            n = n.multiply(base);

            if (c == table[0]) zeros++; // count leading zeros
            else zeros = 0;
        }

        var bytes = bigIntegerToBytesUnsigned(bi);

        if (bytes.length > 1 || bytes[0] !== 0)
            while (zeros-- > 0) bytes.unshift(0); // add leading zeros

        return bytes;
    };

    var bytesToString = function (ba, table) {
        if (!ba.length || (ba.length === 1 && ba[0] === 0))
            return table[0];

        var base = nbv(table.length);

        var bi = bytesUnsignedToBigInteger(ba);
        var chars = [];

        while (bi.compareTo(base) >= 0) {
            var mod = bi.mod(base);
            chars.unshift(table[mod.intValue()]);
            bi = bi.subtract(mod).divide(base);
        }
        chars.unshift(table[bi.intValue()]);

        // Convert leading zeros too.
        for (var i = 0; i < ba.length; i++) {
            if (ba[i] === 0x00) {
                chars.unshift(table[0]);
            } else break;
        }

        return chars.join('');
    };

    var bytesToWords = function (ba) {
        for (var words = [], i = 0, b = 0; i < ba.length; i++, b += 8)
            words[b >>> 5] |= ba[i] << (24 - b % 32);
        return words;
    };

    var wordsToBytes = function (wa) {
        for (var bytes = [], b = 0; b < wa.length * 32; b += 8)
            bytes.push((wa[b >>> 5] >>> (24 - b % 32)) & 0xFF);
        return bytes;
    };

    var wordArrayToBytes = function (wa) {
        return wordsToBytes(wa.words).slice(0, wa.sigBytes);
    };

    var bytesToWordArray = function (ba) {
        return CryptoJS.lib.WordArray.create(bytesToWords(ba), ba.length);
    };

    var numToVarInt = function (i) {
        if (i < 0xfd) {
            // unsigned char
            return [i];
        } else if (i <= 1 << 16) {
            // unsigned short (LE)
            return [0xfd, i >>> 8, i & 255];
        } else if (i <= 1 << 32) {
            // unsigned int (LE)
            return [0xfe].concat(wordsToBytes([i]));
        } else {
            // unsigned long long (LE)
            return [0xff].concat(wordsToBytes([i >>> 32, i]));
        }
    };

    var bytesToCheck = function (ba, version) {
        var bytes = ba.slice(0);

        if (version !== undefined)
            bytes.unshift(version);

        var checksum = Verso.Cryptography.SHASHA256(bytes);

        return bytes.concat(checksum.slice(0, 4));
    };

    var checkToBytes = function (ba, version) {
        if (!Array.isArray(version)) { version = [version]; }

        if (version !== undefined && !version.some(function (v) { return ba[0] === v; })) {
            throw new Verso.Error("Version mismatch!");
        }

        var bytes = ba.slice(0, ba.length - 4);
        var checksum = ba.slice(ba.length - 4, ba.length);

        var chk = Verso.Cryptography.SHASHA256(bytes).slice(0, 4);
        for (var i = 0; i < 4; i++) if (chk[i] != checksum[i]) throw new Verso.Error("Checksum mismatch!");

        if (version === undefined)
            return bytes;
        return bytes.slice(1);
    };

    return {
        base16ToBytes: function (s) {
            return wordArrayToBytes(CryptoJS.enc.Hex.parse(s));
        },
        bytesToBase16: function (ba) {
            return CryptoJS.enc.Hex.stringify(bytesToWordArray(ba));
        },
        base58ToBytes: function (s) {
            return stringToBytes(s, Base58Table);
        },
        bytesToBase58: function (ba) {
            return bytesToString(ba, Base58Table);
        },
        base64ToBytes: function (s) {
            return wordArrayToBytes(CryptoJS.enc.Base64.parse(s));
        },
        bytesToBase64: function (ba) {
            return CryptoJS.enc.Base64.stringify(bytesToWordArray(ba));
        },
        bytesToBase64Url: function(ba) {
            return CryptoJS.enc.Base64.stringify(bytesToWordArray(ba)).replace("+", "-").replace("/", "_").replace("=", "");
        },
        base94ToBytes: function (s) {
            return stringToBytes(s, Base94Table);
        },
        bytesToBase94: function (ba) {
            return bytesToString(ba, Base94Table);
        },
        bytesToUtf8: function(ba) {
            return CryptoJS.enc.Utf8.stringify(bytesToWordArray(ba));
        },
        utf8ToBytes: function (s) {
            return wordArrayToBytes(CryptoJS.enc.Utf8.parse(s));
        },
        wordsToBytes: wordsToBytes,
        bytesToWords: bytesToWords,
        wordArrayToBytes: wordArrayToBytes,
        bytesToWordArray: bytesToWordArray,
        bigIntegerToBytesUnsigned: bigIntegerToBytesUnsigned,
        bytesUnsignedToBigInteger: bytesUnsignedToBigInteger,
        bigIntegerToBytesSigned: bigIntegerToBytesSigned,
        bytesSignedToBigInteger: bytesSignedToBigInteger,
        integerToBytesUnsigned: integerToBytesUnsigned,
        numToVarInt: numToVarInt,
        bytesToCheck: bytesToCheck,
        checkToBytes: checkToBytes
    };
})();
