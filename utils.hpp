//
// Created by Kendrick Nguyen on 3/8/25.
//

#ifndef BREAKING_RSA_UTILS_HPP
#define BREAKING_RSA_UTILS_HPP

#include <algorithm>
#include <gmpxx.h>
#include <string>

namespace Utils {

    const size_t NUMERIC_BASE = 26;

    // Encode message to base 26 and store it in an arbitrary-precision integer
    void base26_encode(const std::string& message, mpz_class& encodedMessage) {
        std::string reversedMessage = message;
        std::reverse(reversedMessage.begin(), reversedMessage.end());

        encodedMessage = 0;

        for (size_t pos = 0; pos < reversedMessage.size(); ++pos) {
            auto alphabetIndex = static_cast<unsigned long>(reversedMessage[pos] - 'a');

            mpz_class basePower;
            mpz_ui_pow_ui(basePower.get_mpz_t(), NUMERIC_BASE, pos);

            encodedMessage += basePower * alphabetIndex;
        }
    }

    // Decode base 26 encoded message back to a string
    void base26_decode(const mpz_class& decryptedMessage, std::string& recoveredMessage) {
        mpz_class quotient = decryptedMessage;
        recoveredMessage.clear();

        while (quotient > 0) {
            mpz_class remainder = quotient % NUMERIC_BASE;
            char decodedChar = static_cast<char>(remainder.get_ui() + 'a');
            recoveredMessage.push_back(decodedChar);
            quotient /= NUMERIC_BASE;
        }

        std::reverse(recoveredMessage.begin(), recoveredMessage.end());
    }


}

#endif //BREAKING_RSA_UTILS_HPP
