We using OpenSSL library called:

libcrypto

pipeline
   ↓
controller
   ↓ encrypt
UNIX socket
   ↓ decrypt
module process
   ↓ encrypt
UNIX socket
   ↓ decrypt
controller
   ↓
pipeline