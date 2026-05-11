#include "kdf.h"


vector<unsigned char> KDF_HKDF_SHA256(
    const vector<unsigned char>& shared_secret,
    const vector<unsigned char>& salt,
    const vector<unsigned char>& info,
    size_t key_len
) {
    vector<unsigned char> key(key_len);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        throw runtime_error("HKDF context creation failed");

    if (EVP_PKEY_derive_init(pctx) <= 0)
        throw runtime_error("HKDF init failed");

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        throw runtime_error("HKDF set digest failed");

    if (EVP_PKEY_CTX_set1_hkdf_salt(
            pctx,
            salt.data(),
            salt.size()) <= 0)
        throw runtime_error("HKDF set salt failed");
    if (EVP_PKEY_CTX_set1_hkdf_key(
            pctx,
            shared_secret.data(),
            shared_secret.size()) <= 0)
        throw runtime_error("HKDF set key failed");

    if (EVP_PKEY_CTX_add1_hkdf_info(
            pctx,
            info.data(),
            info.size()) <= 0)
        throw runtime_error("HKDF set info failed");

    size_t out_len = key_len;

    if (EVP_PKEY_derive(pctx, key.data(), &out_len) <= 0)
        throw runtime_error("HKDF derive failed");

    EVP_PKEY_CTX_free(pctx);

    return key;
}
