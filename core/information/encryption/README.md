We using OpenSSL library called:

libcrypto


module process 1
   ↓ encrypt
UNIX or Network socket
   ↓ decrypt
module process 2
   ↓ encrypt
UNIX or Network socket
   ↓ decrypt
module process (1 or x)
