//
// Created by Kendrick Nguyen on 3/8/25.
//

#ifndef BREAKING_RSA_RSA_HPP
#define BREAKING_RSA_RSA_HPP

#include <gmpxx.h>
#include <stdexcept>

namespace RSA {

    struct PublicKeys {
        mpz_class N_KEY;
        mpz_class E_KEY;
    };

    struct PrivateKeys {
        mpz_class P_KEY;
        mpz_class Q_KEY;
        mpz_class D_KEY;
    };

    class RSA {
    public:
        RSA(const mpz_class& p, const mpz_class& q, const mpz_class& d)
                : p_(p), q_(q), d_(d) {

            N_ = p_ * q_;
            phi_ = (p_ - 1) * (q_ - 1);

            if (!modInverse(e_, d_, phi_)) {
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

        void encrypt(mpz_class& result, const mpz_class& message) const {
            modExponentiation(result, message, e_, N_);
        }

        void decrypt(mpz_class& result, const mpz_class& ciphertext) const {
            modExponentiation(result, ciphertext, d_, N_);
        }

        static void modExponentiation(mpz_class& result, const mpz_class& base, const mpz_class& exponent, const mpz_class& mod) {
            mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exponent.get_mpz_t(), mod.get_mpz_t());
        }

        static bool modInverse(mpz_class& result, const mpz_class& d, const mpz_class& phi) {
            return mpz_invert(result.get_mpz_t(), d.get_mpz_t(), phi.get_mpz_t()) != 0;
        }

    private:
        mpz_class p_, q_, d_, N_, phi_, e_;
        PublicKeys publicKeys_;
        PrivateKeys privateKeys_;
    };

};

#endif //BREAKING_RSA_RSA_HPP
