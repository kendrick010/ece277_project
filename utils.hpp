//
// Created by Kendrick Nguyen on 3/8/25.
//

#ifndef BREAKING_RSA_UTILS_HPP
#define BREAKING_RSA_UTILS_HPP

#include <algorithm>
#include <cstddef>
#include <cmath>
#include <sstream>
#include <string>

namespace Utils {

    const size_t NUMERIC_BASE = 26;

    void base26_encode(const char* message, __uint128_t& encodedMessage) {
        const size_t size = std::strlen(message);
        char* copy = new char[size + 1];
        std::strcpy(copy, message);
        std::reverse(copy, copy + size);

        encodedMessage = 0;

        for (size_t pos{0}; copy[pos] != '\0'; ++pos) {
            auto alphabetIndex = static_cast<__uint128_t>(copy[pos] - 'a');
            encodedMessage += alphabetIndex * static_cast<__uint128_t>(std::pow(NUMERIC_BASE, pos));
        }

        delete[] copy;
    }

    void base26_decode(const __uint128_t decryptedMessage, char* recoveredMessage) {
        __uint128_t quotient{decryptedMessage}, remainder;
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

    std::string uint128_to_string(__uint128_t value) {
        unsigned long long high = value >> 64;
        unsigned long long low = value & 0xFFFFFFFFFFFFFFFF;

        std::ostringstream oss;
        oss << high << low;
        return oss.str();
    }

}

#endif //BREAKING_RSA_UTILS_HPP
