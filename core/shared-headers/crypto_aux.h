#ifndef CRYPTO_AUX_H
#define CRYPTO_AUX_H
#include <iostream>
#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include <cstring>
#include "Encryption_using_DH_fn.h"

std::vector<uint8_t> aes256_cbc_encrypt(
    const std::vector<uint8_t>& key,              
    const std::vector<uint8_t>& plaintext)        
{
    if (key.size() != 32) throw std::invalid_argument("Key must be 32 bytes (AES-256).");

    const int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc()); 
    std::vector<uint8_t> iv(iv_len);
    if (RAND_bytes(iv.data(), iv_len) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> ciphertext;
    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        // Reserve output buffer: plaintext size + block size
        int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
        ciphertext.resize(iv_len + plaintext.size() + block_size);

        // Copy IV to beginning of output
        std::memcpy(ciphertext.data(), iv.data(), iv_len);

        int out_len1 = 0;
        if (plaintext.size() > 0) {
            if (EVP_EncryptUpdate(ctx,
                                  ciphertext.data() + iv_len,
                                  &out_len1,
                                  plaintext.data(),
                                  static_cast<int>(plaintext.size())) != 1) {
                throw std::runtime_error("EVP_EncryptUpdate failed");
            }
        } else {
            out_len1 = 0;
        }

        int out_len2 = 0;
        if (EVP_EncryptFinal_ex(ctx,
                                ciphertext.data() + iv_len + out_len1,
                                &out_len2) != 1) {
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }

        // Resize ciphertext to actual length (IV + encrypted data)
        ciphertext.resize(iv_len + out_len1 + out_len2);
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

#include <openssl/sha.h>

std::vector<uint8_t> sha256_digest(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH); // 32

    // Using OpenSSL SHA256() convenience function
    if (!SHA256(data.data(), data.size(), digest.data())) {
        throw std::runtime_error("SHA256 computation failed");
    }

    return digest;
}

int dh_handshake_peer(int& sock,std::vector<unsigned char>& peer_shared_secret) {
	if (sock<0) {
		cerr << "The socket is not valid. Maybe closed?\n";
		return -1;
	}
	try {
	const char* p="23";
	const char* g="5";
	DHWrapper peer(p,g);
	peer.generateKeys();
	auto this_peer_pub=peer.getPublicKey();
	send(sock,this_peer_pub.data(),sizeof(this_peer_pub.data()),0); 
	vector<unsigned char> second_peer(256);
	recv(sock,second_peer.data(),second_peer.size(),0);
	peer.computeSharedSecret(second_peer);
	peer_shared_secret=peer.getSharedSecret();
	}
	catch (const std::exception& e) {
		cerr << "Diffie-Hellman Failed: " << e.what() << "\n";
		return -2;
	}
	return 0;
}

#include "aesgcm.h"

vector<unsigned char> aes_gcm128_encrypt(vector<unsigned char>& plaintext,vector<unsigned char>& key,vector<unsigned char>& iv,vector<unsigned char>& tag) {
	vector<unsigned char> ciphertext;
	try {
	AESGCM::generateIV(iv); 
	ciphertext=AESGCM::encrypt(plaintext,key,iv,tag);
	}
	catch (const std::exception& e) {
		cerr << "Error in AES-GCM128 encryption: " << e.what() << "\n";
		vector<unsigned char> result={'e','r','r'};
		return result;
	}
	return ciphertext;
}

vector<unsigned char> aes_gcm128_decrypt(vector<unsigned char>& ciphertext,vector<unsigned char> key,vector<unsigned char>& iv,vector<unsigned char>& tag) {
	vector<unsigned char> plaintext;
	try {
		plaintext=AESGCM::decrypt(ciphertext,key,iv,tag);
	}
	catch (const std::exception& e) {
		cerr << "Error in AES-GCM128 decryption: " << e.what() << "\n";
		vector<unsigned char> fail_result={'e','r','r'};
		return fail_result;
	}
	return plaintext;
}

#include "kdf.h"



#endif
