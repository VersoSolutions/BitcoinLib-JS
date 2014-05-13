/*

BitcoinLib-JS
github.com/VersoSolutions/BitcoinLib-JS

Copyright (c) 2013 Verso Solutions LLC

This file is part of BitcoinLib.

BitcoinLib is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

BitcoinLib is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with BitcoinLib.  If not, see <http://www.gnu.org/licenses/>.

*/

/**
 * Verso library top-level namespace
 * @namespace
 */
var Verso = Verso || {
    /**
     * Bitcoin-related functions
     * @namespace
     * @memberOf Verso
    */
    Bitcoin: {
        /**
         * Bitcoin data providers
         * @namespace
         * @memberOf Verso.Bitcoin
         */
        Providers: {},
        /**
         * Bitcoin utilities
         * @namespace
         * @memberOf Verso.Bitcoin
         */
        Utils: {}
    },
    Class: {
        inherit: function (o) {
            function F() {}
            F.prototype = o;
            return new F();
        }
    },
    /**
    * Cryptography-related functions
    * @namespace
    * @memberOf Verso.Helpers
    */
    Cryptography: {},
    /**
    * Encoding-related functions
    * @namespace
    * @memberOf Verso.Helpers
    */
    Encoding: {},
    /**
     * General settings
     * @namespace
     * @memberOf Verso
     */
    Settings: {}
};

/**
 * Generic error
 *
 * @constructor
 * @param {string}  [msg] Error description
 */
Verso.Error = function (msg) {
    this.getMessage = function () { return msg; };
};
Verso.Error.prototype.toString = function () { return this.getMessage(); };

/**
 * Balance related error (e.g., insufficient funds)
 *
 * @constructor
 * @param {string}  [msg] Error description
 */
Verso.BalanceError = function (msg) {
    Verso.Error.call(this, msg);
};
Verso.BalanceError.prototype = Verso.Class.inherit(Verso.Error.prototype);

/**
 * Connection error
 *
 * @constructor
 * @param {string}  [msg] Error description
 */
Verso.ConnectionError = function (msg, xhr) {
    Verso.Error.call(this, msg);
    this.xhr = xhr;
};
Verso.ConnectionError.prototype = Verso.Class.inherit(Verso.Error.prototype);

/**
 * Authentication error
 *
 * @constructor
 * @param {string}  [msg] Error description
 */
Verso.CredentialsError = function (msg) {
    Verso.Error.call(this, msg);
};
Verso.CredentialsError.prototype = Verso.Class.inherit(Verso.Error.prototype);