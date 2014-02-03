var Cryptography = Verso.Cryptography;
var Encoding = Verso.Encoding;

Cryptography.addPureEntropy(Cryptography.SHA256([0]));

test("Encoding", function(assert) {
    expect(8);

    // Test parameters
    var bytes = [0,222,165,216,36,178,90,201,206,63,78,171,254,14,62,105,95,242,92,106,89,155,141,120,40,253,194,120,200,151,230,55,39];
    var string16 = "00dea5d824b25ac9ce3f4eabfe0e3e695ff25c6a599b8d7828fdc278c897e63727";
    var string58 = "1Fz8BamU1v5PX1Fdj5Tv6mVYzLr2LRu26dUf5bm1Jr3hQ";
    var string64 = "AN6l2CSyWsnOP06r/g4+aV/yXGpZm414KP3CeMiX5jcn";
    var string94 = "!\",e\\o--/vgARt4n]i^`O/MsGA84MEH,PBRE~{=yH";

    assert.equal(Encoding.bytesToBase16(bytes), string16, "Base 16: Encoding");
    assert.deepEqual(Encoding.base16ToBytes(string16), bytes, "Base 16: Decoding");
    assert.equal(Encoding.bytesToBase58(bytes), string58, "Base 58: Encoding");
    assert.deepEqual(Encoding.base58ToBytes(string58), bytes, "Base 58: Decoding");
    assert.equal(Encoding.bytesToBase64(bytes), string64, "Base 64: Encoding");
    assert.deepEqual(Encoding.base64ToBytes(string64), bytes, "Base 64: Decoding");
    assert.equal(Encoding.bytesToBase94(bytes), string94, "Base 94: Encoding");
    assert.deepEqual(Encoding.base94ToBytes(string94), bytes, "Base 94: Decoding");
});

test("AES", function(assert) {
    expect(3);

    // Test parameters with padding
    var plaintext = [0,144,171,95,22,2,166,15,91,221,76,129,0,185,232,58,240,215,140,226,115,222,240,101,127];
    var key = [222,165,216,36,178,90,201,206,63,78,171,254,14,62,105,95,242,92,106,89,155,141,120,40,253,194,120,200,151,230,55,39]; // 256 bits
    var iv = [145,218,21,204,4,27,187,247,37,136,191,141,117,104,189,79]; // 128 bits
    var ciphertext = [159,6,9,72,217,67,68,0,209,255,160,56,9,153,229,192,194,187,136,132,199,165,51,113,138];

    assert.deepEqual(Cryptography.aesEncrypt(plaintext, key, iv), ciphertext, "Encryption with predefined IV");
    assert.deepEqual(Cryptography.aesDecrypt(ciphertext, key, iv), plaintext, "Decryption with predefined IV");
    assert.deepEqual(Cryptography.aesDecrypt(Cryptography.aesEncrypt(plaintext, key), key), plaintext, "Encryption/Decryption with concatenated IV");
});

test("RSA", function(assert) {
    expect(1);

    // Test parameters
    var plaintext = [0,144,171,95,22,2,166,15,91,221,76,129,0,185,232,58,240,215,140,226,115,222,240,101,127];
    var modulus = "b3df71c5500a3d59a6004eb2d1cae4cbc97cd7b420e7c7c4cf2d1ede801145daa407553136e7afe985b5def047be04e4ac61e7e400bd08207fb66e6e255e5df0239ca2c60e16bff13b01c54d239190a3df3975c3c9f5d555f67a9a412e9f27ec444cfd3d10d618588e40fb6ec2d1c3f097f923d7c5c4b1b8130d9e91e25603e4b7d622ef15983d5c45f9a11e00223aaebed6c6e78d23500d012fef9aa36efa59a82c74277961447df4eb21c646341970d98a38268f3205ac5d17bd3bfe46e5eb1f6d1ac84b1f7bb5bd89a22bd5e9ca1c8fb1a618ee1b61480e7df3c518c3cdaccb7782a247d970f34fdeee4d76a11591da9c3324d91719ea39c181fe0a99bd0b";
    var exponent = "010001";

    ok(Cryptography.rsaEncrypt(plaintext,modulus,exponent), "Encryption");
});

test("PBKDF2", function(assert) {
    expect(1);

    // Test parameters
    var password = "this is my password"; // TODO: try some unconventional characters
    var salt = [185,116,231,174,144,168,94,22,66,101,248,240,5,19,254,176];
    var iterations = 1000;
    var key = [116,123,17,162,240,143,88,173,178,112,168,119,7,25,234,245,109,107,241,235,33,176,238,10,197,101,240,114,82,138,99,90];

    assert.deepEqual(Cryptography.PBKDF2(password, salt, iterations), key, "Key derivation");
});

test("scrypt", function (assert) {
    expect(2);

    var tv1 = [119,214,87,98,56,101,123,32,59,25,202,66,193,138,4,151,241,107,72,68,227,7,74,232,223,223,250,63,237,226,20,66,252,208,6,157,237,9,72,248,50,106,117,58,15,200,31,23,232,211,224,251,46,13,54,40,207,53,226,12,56,209,137,6];
    var tv2 = [253,186,190,28,157,52,114,0,120,86,231,25,13,1,233,254,124,106,215,203,200,35,120,48,231,115,118,99,75,55,49,98,46,175,48,217,46,34,163,136,111,241,9,39,157,152,48,218,199,39,175,185,74,131,238,109,131,96,203,223,162,204,6,64];
    var tv3 = [112,35,189,203,58,253,115,72,70,28,6,205,129,253,56,235,253,168,251,186,144,79,142,62,169,181,67,246,84,93,161,242,213,67,41,85,97,63,15,207,98,212,151,5,36,42,154,249,230,30,133,220,13,101,30,64,223,207,1,123,69,87,88,135];
    var tv4 = [33,1,203,155,106,81,26,174,173,219,190,9,207,112,248,129,236,86,141,87,74,47,253,77,171,229,238,152,32,173,170,71,142,86,253,143,75,165,208,159,250,28,109,146,124,64,244,195,55,48,64,73,232,169,82,251,203,244,92,111,167,122,65,164];

    assert.deepEqual(Cryptography.scrypt("", Verso.Encoding.utf8ToBytes(""), 16, 1, 1, 64*8), tv1);
    assert.deepEqual(Cryptography.scrypt("password", Verso.Encoding.utf8ToBytes("NaCl"), 1024, 8, 16, 64*8), tv2);
    //assert.deepEqual(Cryptography.scrypt("pleaseletmein", Verso.Encoding.utf8ToBytes("SodiumChloride"), 16384, 8, 1, 64*8), tv3);
    //assert.deepEqual(Cryptography.scrypt("pleaseletmein", Verso.Encoding.utf8ToBytes("SodiumChloride"), 1048576, 8, 1, 64*8), tv4);
});

test("Shamir's secret sharing", function(assert) {
    expect(2);

    var shares = [[1,4,112,86,41,29,58,34,70,167,149,170,121,221,89,52,133,61,54,125,138,3,94,101,188,52,122,135,96,222,252],[2,11,224,172,104,188,49,88,223,126,112,53,149,80,32,189,45,252,41,230,90,43,251,182,2,159,102,198,250,39,229],[3,14,144,250,87,40,195,133,168,194,216,64,58,43,252,49,190,72,215,100,225,51,152,12,104,13,153,249,140,112,25]];
    var secret = [0,0,22,137,200,255,49,27,61,223,214,166,133,184,22,137,200,255,49,27,61,223,214,166,133,184,22,137,0];

    assert.deepEqual(Cryptography.secretCombine(shares), secret, "Secret: Combination");
    assert.deepEqual(Cryptography.secretCombine(Cryptography.secretShare(secret,3,2)), secret, "Secret: Sharing/Combination");
});

test("Bitcoin: Endpoint", function(assert) {
    expect(5);

    // Test parameters
    var key = [32,131,67,83,151,81,219,47,99,252,163,163,58,78,96,158,134,146,60,153,224,253,223,102,241,160,75,61,6,168,160,72];
    var hash = [203,146,205,25,123,53,130,60,120,231,66,219,70,226,130,132,121,246,157,100,11,128,16,43,90,250,47,244,159,118,171,79];
    var publicHash = [152,250,113,111,157,116,221,110,52,166,101,82,54,68,66,223,23,224,204,246];
    var address = "1EwsjFXmCfuv5ZAZEKH18ofnjCCMMEdmaE";
    var pub = [4,209,126,186,122,113,221,43,12,38,188,185,81,135,106,143,216,100,194,231,18,79,123,165,83,199,1,1,191,115,1,46,95,160,214,146,74,240,127,182,118,214,57,179,44,166,214,92,54,69,114,55,61,191,68,188,120,128,109,15,228,201,25,164,229];
    var priv = [32,131,67,83,151,81,219,47,99,252,163,163,58,78,96,158,134,146,60,153,224,253,223,102,241,160,75,61,6,168,160,72];
    var privString = "5J4c5MpVbRvxRzZNB3hu7LbAdaqjdbVeTkomMpRZUMgEAaSzef7";

    var e = new Verso.Bitcoin.Endpoint(key);

    assert.deepEqual(e.getPublicHash(), publicHash, "Address: Public hash");
    assert.deepEqual(e.getAddress(), address, "Address: String");
    assert.deepEqual(e.getPublic(), pub, "Public key: DER");
    assert.deepEqual(e.getPrivate(), priv, "Private key: Bytes");
    assert.deepEqual(e.getPrivateCheck(), privString, "Private key: String");
});

test("Bitcoin: BIP 0032", function(assert) {
    expect(8);

    // Test parameters
    var seed = [255,252,249,246,243,240,237,234,231,228,225,222,219,216,213,210,207,204,201,198,195,192,189,186,183,180,177,174,171,168,165,162,159,156,153,150,147,144,141,138,135,132,129,126,123,120,117,114,111,108,105,102,99,96,93,90,87,84,81,78,75,72,69,66];
    var km = [75,3,214,252,52,4,85,179,99,245,16,32,173,62,204,164,240,133,2,128,207,67,108,112,199,39,146,63,109,180,108,62];
    var Km = [3,203,202,169,201,140,135,122,38,151,125,0,130,92,149,106,35,142,141,221,251,211,34,204,228,247,75,11,91,214,172,228,167];
    var km0 = [171,231,74,152,246,199,234,190,224,66,143,83,121,143,10,184,170,27,211,120,115,153,144,65,112,60,116,47,21,172,126,30];
    var Km0 = [2,252,158,90,240,172,141,155,60,236,254,42,136,142,33,23,186,61,8,157,133,133,136,108,156,130,107,107,34,169,141,18,234];
    var km0x = [135,124,119,154,217,104,113,100,233,194,244,240,244,255,3,64,129,67,146,51,6,147,206,149,165,143,225,143,213,46,110,147];
    var Km0x = [3, 192, 30, 116, 37, 100, 123, 222, 250, 130, 177, 45, 155, 173, 94, 62, 104, 101, 190, 224, 80, 38, 148, 185, 76, 165, 139, 102, 106, 188, 10, 92, 59];
    var km0x123 = [187, 125, 57, 189, 184, 62, 207, 88, 242, 253, 130, 182, 217, 24, 52, 28, 190, 244, 40, 102, 30, 240, 26, 185, 124, 40, 164, 132, 33, 37, 172, 35];
    var Km0x123 = [2, 77, 144, 46, 26, 47, 199, 168, 117, 90, 181, 182, 148, 197, 117, 252, 231, 66, 196, 141, 159, 241, 146, 230, 61, 245, 25, 62, 76, 122, 254, 31, 156];

    var m = new Verso.Bitcoin.MasterEndpoint(seed);

    var m0 = m.getChild(0, true);
    var m0x = m0.getChild(2147483647, false);
    var m0x123 = m0x.getChild(1, true).getChild(2147483646, false).getChild(2, true);

    assert.deepEqual(m.getPrivate(), km, "m: Private key");
    assert.deepEqual(m.getPublic(true), Km, "m: Public key (compressed)");
    assert.deepEqual(m0.getPrivate(), km0, "m/0: Private key");
    assert.deepEqual(m0.getPublic(true), Km0, "m/0: Public key (compressed)");
    assert.deepEqual(m0x.getPrivate(), km0x, "m/0/2147483647': Private key");
    assert.deepEqual(m0x.getPublic(true), Km0x, "m/0/2147483647': Public key (compressed)");
    assert.deepEqual(m0x123.getPrivate(), km0x123, "m/0/2147483647'/1/2147483646'/2: Private key");
    assert.deepEqual(m0x123.getPublic(true), Km0x123, "m/0/2147483647'/1/2147483646'/2: Public key (compressed)");

});
