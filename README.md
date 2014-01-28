BitcoinLib-JS
=============

Javascript library for Bitcoin wallet management

##Development

First, run `npm install` from the root of the repository to install or update dependencies.

Run `grunt` to build the library to `dist/bitcoinlib.min.js`.

##Dependencies

BitcoinLib-JS relies on several other JavaScript libraries:
- [CryptoJS](https://code.google.com/p/crypto-js/) for all the basic cryptographic functions
- [SJCL](https://github.com/bitwiseshiftleft/sjcl) for entropy collection and key derivation functions
- [JSBN](http://www-cs-students.stanford.edu/~tjw/jsbn/) for public-key cryptography (RSA and ECC)
- [secrets.js](https://github.com/amper5and/secrets.js/) for Shamir's secret sharing scheme
- [QUnit](http://qunitjs.com/) for unit testing

##License

This software is released under the GNU GPL v3 license.