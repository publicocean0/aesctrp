# aesctrp
AES CTR encryption with parametric nonce and sequence

It permits to encrypt a packet defined as Buffer Array , evoiding the middle attack by using a embedded counter (generated by current date or by a parameter) and a external sequence counter (optional). In fact when you send multiple packets using a constant password you could guess the password if there are multiple packets sent similars in the network. The AES version removes this problem by traditional AES algorithm without the necessity to use a counter in the protocol, foreseable by receiver.
<pre>
var nonce=10000;
var sequence=1;
var buf=AesCtrP.encrypt(input, password, 256,sequence,nonce)
var result=AesCtrP.decrypt(buf, password, 256,sequence);
console.log(result);
</pre>
