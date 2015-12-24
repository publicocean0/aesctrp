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

alert(AesCtrP.leadingZeros(1));
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



AesCtrP.base64ArrayBuffer=function(base64) {
    var binary_string =  window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++)        {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
};
AesCtrP.arrayBufferBase64=function(arrayBuffer) {
var base64 = ''
var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
var bytes = new Uint8Array(arrayBuffer)
var byteLength = bytes.byteLength
var byteRemainder = byteLength % 3
var mainLength = byteLength - byteRemainder
var a, b, c, d
var chunk
// Main loop deals with bytes in chunks of 3
for (var i = 0; i < mainLength; i = i + 3) {
// Combine the three bytes into a single integer
chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
// Use bitmasks to extract 6-bit segments from the triplet
a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
b = (chunk & 258048) >> 12 // 258048 = (2^6 - 1) << 12
c = (chunk & 4032) >> 6 // 4032 = (2^6 - 1) << 6
d = chunk & 63 // 63 = 2^6 - 1
// Convert the raw binary segments to the appropriate ASCII encoding
base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
}
// Deal with the remaining bytes and padding
if (byteRemainder == 1) {
chunk = bytes[mainLength]
a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2
// Set the 4 least significant bits to zero
b = (chunk & 3) << 4 // 3 = 2^2 - 1
base64 += encodings[a] + encodings[b] + '=='
} else if (byteRemainder == 2) {
chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]
a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
b = (chunk & 1008) >> 4 // 1008 = (2^6 - 1) << 4
// Set the 2 least significant bits to zero
c = (chunk & 15) << 2 // 15 = 2^4 - 1
base64 += encodings[a] + encodings[b] + encodings[c] + '='
}
return base64
};

AesCtrP.arrayBufferString=function(array) {
    var out, i, len, c;
    var char2, char3;

    out = "";
    len = array.length;
    i = 0;
    while(i < len) {
    c = array[i++];
    switch(c >> 4)
    { 
      case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
        // 0xxxxxxx
        out += String.fromCharCode(c);
        break;
      case 12: case 13:
        // 110x xxxx   10xx xxxx
        char2 = array[i++];
        out += String.fromCharCode(((c & 0x1F) << 6) | (char2 & 0x3F));
        break;
      case 14:
        // 1110 xxxx  10xx xxxx  10xx xxxx
        char2 = array[i++];
        char3 = array[i++];
        out += String.fromCharCode(((c & 0x0F) << 12) |
                       ((char2 & 0x3F) << 6) |
                       ((char3 & 0x3F) << 0));
        break;
    }
    }

    return out;
};

AesCtrP.stringArrayBuffer=function(stringToEncode) {
              stringToEncode = stringToEncode.replace(/\r\n/g,"\n");
              var utftext = [];
              

              for (var n = 0; n < stringToEncode.length; n++) {

                  var c = stringToEncode.charCodeAt(n);

                  if (c < 128) {
                      utftext[utftext.length]= c;
                  }
                  else if((c > 127) && (c < 2048)) {
                      utftext[utftext.length]= (c >> 6) | 192;
                      utftext[utftext.length]= (c & 63) | 128;
                  }
                  else {
                      utftext[utftext.length]= (c >> 12) | 224;
                      utftext[utftext.length]= ((c >> 6) & 63) | 128;
                      utftext[utftext.length]= (c & 63) | 128;
                  }

              }
              return utftext;  
 };
 



