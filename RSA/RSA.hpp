//
// Created by Kendrick Nguyen on 3/8/25.
//

#ifndef BREAKING_RSA_RSA_HPP
#define BREAKING_RSA_RSA_HPP

#include <algorithm>
#include <stdexcept>

namespace RSA {

    struct PublicKeys {
        uint64_t N_KEY;
        uint64_t E_KEY;
    };

    struct PrivateKeys {
        uint64_t P_KEY;
        uint64_t Q_KEY;
        uint64_t D_KEY;
    };

    class RSA {
    public:
        RSA(uint64_t p, uint64_t q, uint64_t d)
                : p_(p), q_(q), d_(d), N_(p * q), phi_((p - 1) * (q - 1)) {
            if (p == q) {
                throw std::invalid_argument("p and q must be distinct primes.");
            }

            e_ = modInverse(d, phi_);
            if (e_ == 0) {
                throw std::invalid_argument("Invalid private key d: no modular inverse exists.");
            }

            publicKeys_ = {N_, e_};
            privateKeys_ = {p_, q_, d_};
        }

        PublicKeys getPublicKeys() const {
            return publicKeys_;
        }

        PrivateKeys getPrivateKeys() const {
            return privateKeys_;
        }

        uint64_t encrypt(uint64_t encodedMessage) const {
            if (encodedMessage > N_ - 1) {
                throw std::invalid_argument("Warning: Encoded message is greater than N.");
            }

            return modExponentiation(encodedMessage, e_, N_);
        }

        uint64_t decrypt(uint64_t encryptedMessage) const {
            return modExponentiation(encryptedMessage, d_, N_);
        }

        // Fast Modular Exponentiation (Square-and-Multiply)
        static uint64_t modExponentiation(uint64_t base, uint64_t exponent, uint64_t mod) {
            uint64_t result{1};
            base = base % mod;

            while (exponent > 0) {
                // If exponent is odd, multiply base with result
                if (exponent & 1) {
                    result = (result * base) % mod;
                }

                exponent = exponent >> 1;
                base = (base * base) % mod;
            }

            return result;
        }

        // Euclidean modular inverse
        static uint64_t modInverse(uint64_t e, uint64_t phi) {
            uint64_t t{0}, newT{1};
            uint64_t r{phi}, newR{e};

            while (newR != 0) {
                uint64_t quotient{r / newR};

                // Update t and newT using signed arithmetic
                auto tempT{t - quotient * newT};
                t = newT;
                newT = tempT;

                // Update r and newR
                auto tempR{r - quotient * newR};
                r = newR;
                newR = tempR;
            }

            // No modular inverse exists if r > 1
            if (r > 1) return 0;

            return t;
        }

    private:
        uint64_t p_, q_, d_, N_, phi_, e_;
        PublicKeys publicKeys_{};
        PrivateKeys privateKeys_{};
    };

};

#endif //BREAKING_RSA_RSA_HPP