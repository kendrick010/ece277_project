//
// Created by Kendrick Nguyen on 3/8/25.
//

#ifndef BREAKING_RSA_RSA_HPP
#define BREAKING_RSA_RSA_HPP

namespace RSA {

    struct PublicKeys {
        size_t N_KEY;
        size_t E_KEY;
    };

    struct PrivateKeys {
        size_t P_KEY;
        size_t Q_KEY;
        size_t D_KEY;
    };

    class RSA {
    public:
        RSA(size_t p, size_t q, size_t e)
        : p_(p), q_(q), e_(e), N_(p_ * q_), phi_((p_ - 1) * (q_ - 1)), d_(modInverse(e_, phi_)) {}

        PublicKeys encrypt(const unsigned long long encodedMessage) {
            PublicKeys publicPairKey{};
            publicPairKey.N_KEY = N_;
            publicPairKey.E_KEY = e_;

            unsigned long long encryptedMessage = 1;
            for (size_t i = 0; i < e_; ++i) {
                encryptedMessage = (encryptedMessage * encodedMessage) % N_;
            }

            std::cout << "Encrypted Message: " << encryptedMessage << std::endl;

            return publicPairKey;
        }

        unsigned long long decrypt(const unsigned long long encryptedMessage) const {
            unsigned long long decryptedMessage = 1;
            for (size_t i = 0; i < d_; ++i) {
                decryptedMessage = (decryptedMessage * encryptedMessage) % N_;
            }

            return decryptedMessage;
        }

    private:
        size_t p_, q_, e_, N_, phi_, d_;

        // Euclidean modular inverse
        static size_t modInverse(size_t e, size_t phi) {
            size_t t = 0;
            size_t newT = 1;
            size_t r = phi;
            size_t newR = e;

            while (newR != 0) {
                size_t quotient = r / newR;
                t = t - quotient * newT;
                r = r - quotient * newR;

                std::swap(t, newT);
                std::swap(r, newR);
            }

            if (r > 1) return 0;  // No modular inverse exists
            if (t < 0) t = t + phi;

            return t;
        }
    };

};

#endif //BREAKING_RSA_RSA_HPP
