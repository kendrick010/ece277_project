//
// Created by Kendrick Nguyen on 3/8/25.
//

#ifndef BREAKING_RSA_UTILS_HPP
#define BREAKING_RSA_UTILS_HPP

#include <algorithm>
#include <cstddef>
#include <cmath>

namespace Utils {

    const size_t NUMERIC_BASE = 26;

    void base26_encode(const char* message, uint64_t& encodedMessage) {
        const size_t size = std::strlen(message);
        char* copy = new char[size + 1];
        std::strcpy(copy, message);
        std::reverse(copy, copy + size);

        encodedMessage = 0;

        for (size_t pos{0}; copy[pos] != '\0'; ++pos) {
            auto alphabetIndex = static_cast<uint64_t>(copy[pos] - 'a');
            encodedMessage += alphabetIndex * static_cast<uint64_t>(std::pow(NUMERIC_BASE, pos));
        }

        delete[] copy;
    }

    void base26_decode(const uint64_t decryptedMessage, char* recoveredMessage) {
        uint64_t quotient{decryptedMessage}, remainder;
        size_t pos{0};

        while (quotient > 0) {
            remainder = quotient % NUMERIC_BASE;
            quotient /= NUMERIC_BASE;

            recoveredMessage[pos] = char(remainder + 'a');
            ++pos;
        }

        recoveredMessage[pos] = '\0';
        std::reverse(recoveredMessage, recoveredMessage + pos);
    }

}

#endif //BREAKING_RSA_UTILS_HPP
