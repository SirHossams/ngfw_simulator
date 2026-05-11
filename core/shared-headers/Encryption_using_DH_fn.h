#include <openssl/dh.h>
#include <openssl/bn.h>
#include <vector>
#include <stdexcept>

using namespace std;

class DHWrapper {
private:
    DH* dh;
    vector<unsigned char> shared_secret;

public:
    DHWrapper(const char* prime_str, const char* generator_str) {
        dh = DH_new();
        if (!dh) throw runtime_error("DH_new failed");

        BIGNUM* p = NULL;
        BIGNUM* g = NULL;

        BN_dec2bn(&p, prime_str);
        BN_dec2bn(&g, generator_str);

        if (!DH_set0_pqg(dh, p, NULL, g))
            throw runtime_error("Failed to set p and g");
    }

    void generateKeys() {
        if (!DH_generate_key(dh))
            throw runtime_error("Key generation failed");
    }

    vector<unsigned char> getPublicKey() {
        const BIGNUM* pub_key = NULL;
        DH_get0_key(dh, &pub_key, NULL);

        int len = BN_num_bytes(pub_key);
        vector<unsigned char> buffer(len);
        BN_bn2bin(pub_key, buffer.data());

        return buffer;
    }

    void computeSharedSecret(const vector<unsigned char>& peer_pub_bytes) {
        BIGNUM* peer_pub = BN_bin2bn(peer_pub_bytes.data(),
                                     peer_pub_bytes.size(), NULL);

        int size = DH_size(dh);
        shared_secret.resize(size);

        int secret_len = DH_compute_key(shared_secret.data(), peer_pub, dh);
        if (secret_len <= 0)
            throw runtime_error("Shared secret computation failed");

        shared_secret.resize(secret_len);

        BN_free(peer_pub);
    }

    vector<unsigned char> getSharedSecret() {
        return shared_secret;
    }

    ~DHWrapper() {
        DH_free(dh);
    }
};
