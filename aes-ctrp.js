/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  AES Counter-mode implementation in JavaScript                                                 */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


'use strict';



/**
 * AesCtrP: Counter-mode (CTR) wrapper for AES with parametric nonce and sequence.
 *
 * This encrypts a Unicode string to produces a base64 ciphertext using 128/192/256-bit AES.
 *
 * See http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 *
 * @augments Aes
 */
var AesCtrP = {};


AesCtrP.concat=function( buffer1, buffer2 ) {
  var tmp = new Uint8Array( buffer1.byteLength + buffer2.byteLength );
  tmp.set( new Uint8Array( buffer1 ), 0 );
  tmp.set( new Uint8Array( buffer2 ), buffer1.byteLength );
  return tmp;
};


AesCtrP.leadingZeros=function( x)
{
    var n = 0;
    if (x == 0) return 64;
    while (1) {
        if (x < 0) break;
        n ++;
        x=x << 1;
    }
    return n+32;
};
/**
 * Encrypt a text using AES encryption in Counter mode of operation.
 *
 * Unicode multi-byte character safe
 *
 * @param   {string} plaintext - Source text to be encrypted.
 * @param   {string} password - The password to use to generate a key.
 * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
 * @param   {number} sequence - sequence in the protocol (optional).
 * @param   {number} nonce - first part of CTR - counter (optional).
 * @returns {string} Encrypted text.
 *
 * @example
 *   var encr = Aes.Ctr.encrypt('big secret', 'pāşšŵōřđ', 256); // encr: 'lwGl66VVwVObKIr6of8HVqJr'
 */
AesCtrP.encrypt = function(plaintext, password, nBits,sequence,nonce) {
	 sequence=(sequence==null)?8:(64 - AesCtrP.leadingZeros(sequence));
    var blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
    if (!(nBits==128 || nBits==192 || nBits==256)) return ''; // standard allows 128/192/256 bit keys
     password=new Uint8Array(password);
     plaintext=new Uint8Array(plaintext);
    // use AES itself to encrypt password to get cipher key (using plain password as source for key
    // expansion) - gives us well encrypted key (though hashed key might be preferred for prod'n use)
    var nBytes = nBits/8;  // no bytes in key (16/24/32)
    var pwBytes = new Uint8Array(nBytes);
	    var pl=password.length-1;
	    for (var j=0, i=0; i<nBytes;j=j<pl?j+1:0, i++) {  // use 1st 16/24/32 chars of password for key        
	    	pwBytes[i] = password[j];
	    }
    var key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes)); // gives us 16-byte key
    key = AesCtrP.concat(key,key.slice(0, nBytes-16));  // expand key to 16/24/32 bytes long

    // initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A §B.2): [0-1] = millisec,
    // [2-3] = random, [4-7] = seconds, together giving full sub-millisec uniqueness up to Feb 2106
    var counterBlock = new Uint8Array(blockSize);

    if (nonce==null||nonce==undefined) nonce = (new Date()).getTime();  // timestamp: milliseconds since 1-Jan-1970
    var nonceMs = nonce%1000;
    var nonceSec = Math.floor(nonce/1000);
    var nonceRnd = Math.floor(Math.random()*0xffff);
    nonce = nonceMs = nonceSec = nonceRnd = 0;
    var ciphertext =new Uint8Array(plaintext.length+8);
    for (var i=0; i<2; i++) counterBlock[i]   = (nonceMs  >>> i*8) & 0xff;
    for (var i=0; i<2; i++) counterBlock[i+2] = (nonceRnd >>> i*8) & 0xff;
    for (var i=0; i<4; i++) counterBlock[i+4] = (nonceSec >>> i*8) & 0xff;
    for (var i=0; i<8; i++) ciphertext[i]=counterBlock[i];
      // generate key schedule - an expansion of the key into distinct Key Rounds for each round
    var keySchedule = Aes.keyExpansion(key);

    var blockCount = Math.ceil(plaintext.length/blockSize);
  
    for (var b=0; b<blockCount; b++) {
        // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
        // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
        for (var c=0; c<4; c++) counterBlock[15-c] = (b >>> c*8) & 0xff;
        for (var c=0; c<4; c++) counterBlock[15-c-4] = ((b>>>sequence) >>> c*8);

        var cipherCntr = Aes.cipher(counterBlock, keySchedule);  // -- encrypt counter block --

        // block size is reduced on final block
        var blockLength = b<blockCount-1 ? blockSize : (plaintext.length-1)%blockSize+1;
        var index=b*blockSize;
        var bindex=8+index;

        for (var i=0; i<blockLength; i++) {  // -- xor plaintext with ciphered counter char-by-char --
            ciphertext[bindex+i] = cipherCntr[i] ^ plaintext[index+i];
        }

    }
   
    return ciphertext;
}; 


/**
 * Decrypt a text encrypted by AES in counter mode of operation
 *
 * @param   {string} ciphertext - Source text to be encrypted.
 * @param   {string} password - Password to use to generate a key.
 * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
 * @param   {number} sequence - sequence of protocol
 * @returns {string} Decrypted text
 *
 * @example
 *   var decr = Aes.Ctr.encrypt('lwGl66VVwVObKIr6of8HVqJr', 'pāşšŵōřđ', 256); // decr: 'big secret'
 */
AesCtrP.decrypt = function(ciphertext, password, nBits,sequence) {
    var blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
    if (!(nBits==128 || nBits==192 || nBits==256)) return ''; // standard allows 128/192/256 bit keys
  	 sequence=(sequence==null)?8:(64 - AesCtrP.leadingZeros(sequence));

      password=new Uint8Array(password);
     ciphertext=new Uint8Array(ciphertext);
    // use AES itself to encrypt password to get cipher key (using plain password as source for key
    // expansion) - gives us well encrypted key (though hashed key might be preferred for prod'n use)
    var nBytes = nBits/8;  // no bytes in key (16/24/32)
    var pwBytes = new Uint8Array(nBytes);
	    var pl=password.length-1;
	    for (var j=0, i=0; i<nBytes;j=j<pl?j+1:0, i++) {  // use 1st 16/24/32 chars of password for key        
	    	pwBytes[i] = password[j];
	    }

    var key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));
    key = AesCtrP.concat(key,key.slice(0, nBytes-16));  // expand key to 16/24/32 bytes long
    // plaintext will get generated block-by-block into array of block-length strings
    var plaintext = new Uint8Array(ciphertext.length-8);
    // recover nonce from 1st 8 bytes of ciphertext
    var counterBlock = new Array(blockSize);
    for (var i=0; i<8; i++) counterBlock[i] = ciphertext[i];

    // generate key schedule
    var keySchedule = Aes.keyExpansion(key);

    // separate ciphertext into blocks (skipping past initial 8 bytes)
    var blockCount = Math.ceil((ciphertext.length-8) / blockSize);
   


    for (var b=0; b<blockCount; b++) {
        // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
        for (var c=0; c<4; c++) counterBlock[15-c] = ((b) >>> c*8) & 0xff;
        for (var c=0; c<4; c++) counterBlock[15-c-4] = ((b>>>sequence) >>> c*8) & 0xff;

        var cipherCntr = Aes.cipher(counterBlock, keySchedule);  // encrypt counter block
        var index=b*blockSize;
        var bindex=8+index;
        var blockLength = b<blockCount-1 ? blockSize : (plaintext.length-1)%blockSize+1;
        for (var i=0; i<blockLength; i++) {
            // -- xor plaintxt with ciphered counter byte-by-byte --
            plaintext[index+i] = cipherCntr[i] ^ ciphertext[bindex+i];

        }

    }


    return plaintext;
};




 



