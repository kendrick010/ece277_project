//
// Created by Kendrick Nguyen on 3/8/25.
//

#ifndef BREAKING_RSA_RSA_HPP
#define BREAKING_RSA_RSA_HPP

#include <algorithm>
#include <stdexcept>

using ULL = unsigned long long;
using LL = long long;

namespace RSA {

    struct PublicKeys {
        ULL N_KEY;
        ULL E_KEY;
    };

    struct PrivateKeys {
        ULL P_KEY;
        ULL Q_KEY;
        ULL D_KEY;
    };

    class RSA {
    public:
        RSA(ULL p, ULL q, ULL d)
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

        ULL encrypt(ULL encodedMessage) const {
            if (encodedMessage > N_ - 1) {
                throw std::invalid_argument("Warning: Encoded message is greater than N.");
            }

            return modExponentiation(encodedMessage, e_, N_);
        }

        ULL decrypt(ULL encryptedMessage) const {
            return modExponentiation(encryptedMessage, d_, N_);
        }

        // Fast Modular Exponentiation (Square-and-Multiply)
        static ULL modExponentiation(ULL base, ULL exponent, ULL mod) {
            ULL result = 1;
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
        static ULL modInverse(ULL e, ULL phi) {
            LL t = 0;
            LL newT = 1;

            ULL r = phi;
            ULL newR = e;

            while (newR != 0) {
                ULL quotient = r / newR;

                // Update t and newT using signed arithmetic
                LL tempT = t - static_cast<LL>(quotient) * newT;
                t = newT;
                newT = tempT;

                // Update r and newR
                ULL tempR = r - quotient * newR;
                r = newR;
                newR = tempR;
            }

            // No modular inverse exists if r > 1
            if (r > 1) return 0;

            // Ensure the result is positive
            if (t < 0) t += static_cast<LL>(phi);

            return static_cast<ULL>(t);
        }

    private:
        ULL p_, q_, d_, N_, phi_, e_;
        PublicKeys publicKeys_{};
        PrivateKeys privateKeys_{};
    };

};

#endif //BREAKING_RSA_RSA_HPP