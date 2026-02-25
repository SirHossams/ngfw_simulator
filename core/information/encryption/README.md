We using OpenSSL library called:

libcrypto


controller
   ↓ encrypt
UNIX socket
   ↓ decrypt
module process
   ↓ encrypt
UNIX socket
   ↓ decrypt
controller
