#ifndef AESGCM_H
#define AESGCM_H
#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <stdexcept>
#include <iostream>

using namespace std;

class AESGCM {
public:

    static void generateIV(vector<unsigned char>& iv) {
        iv.resize(12);
        if (!RAND_bytes(iv.data(), iv.size()))
            throw runtime_error("IV generation failed");
    }

    static vector<unsigned char> encrypt(
        const vector<unsigned char>& plaintext,
        const vector<unsigned char>& key,
        const vector<unsigned char>& iv,
        vector<unsigned char>& tag
    ) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw runtime_error("CTX error");

        vector<unsigned char> ciphertext(plaintext.size());
        int len;

        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
            throw runtime_error("Init failed");

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL))
            throw runtime_error("IV length error");

        if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()))
            throw runtime_error("Key/IV error");

        if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                               plaintext.data(), plaintext.size()))
            throw runtime_error("Encrypt update failed");

        int ciphertext_len = len;

        if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
            throw runtime_error("Final failed");

        ciphertext_len += len;

        tag.resize(16);
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()))
            throw runtime_error("Tag error");

        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);

        return ciphertext;
    }

    static vector<unsigned char> decrypt(
        const vector<unsigned char>& ciphertext,
        const vector<unsigned char>& key,
        const vector<unsigned char>& iv,
        const vector<unsigned char>& tag
    ) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw runtime_error("CTX error");

        vector<unsigned char> plaintext(ciphertext.size());
        int len;

        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
            throw runtime_error("Init failed");

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL))
            throw runtime_error("IV length error");

        if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()))
            throw runtime_error("Key/IV error");

        if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                               ciphertext.data(), ciphertext.size()))
            throw runtime_error("Decrypt update failed");

        int plaintext_len = len;

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 tag.size(), (void*)tag.data()))
            throw runtime_error("Set tag failed");

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

        EVP_CIPHER_CTX_free(ctx);

        if (ret <= 0) {
            throw runtime_error("Authentication failed!");
        }

        plaintext_len += len;
        plaintext.resize(plaintext_len);

        return plaintext;
    }
};

#endif
