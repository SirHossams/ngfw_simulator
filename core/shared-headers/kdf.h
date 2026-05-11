#ifndef KDF_H
#define KDF_H
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <vector>
#include <stdexcept>

using namespace std;

vector<unsigned char> KDF_HKDF_SHA256(
    const vector<unsigned char>& shared_secret,
    const vector<unsigned char>& salt,
    const vector<unsigned char>& info,
    size_t key_len = 32
);

#endif
