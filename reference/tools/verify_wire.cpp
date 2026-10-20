// SPDX-License-Identifier: AGPL-3.0-only
#include "wutong/core.hpp"
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv) {
    std::string input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    try {
        if (argc >= 2 && std::string(argv[1]) == "--jcs") {
            bool unicode_keys = (argc >= 3 && std::string(argv[2]) == "--unicode-keys");
            std::cout << wutong::jcs_canonicalize(input, unicode_keys);
            return 0;
        }
        if (argc >= 2 && std::string(argv[1]) == "--dcbor-hex") {
            bool unicode_keys = (argc >= 3 && std::string(argv[2]) == "--unicode-keys");
            std::cout << wutong::dcbor_to_hex(input, unicode_keys);
            return 0;
        }
        if (argc >= 2 && std::string(argv[1]) == "--dcbor-decode-hex") {
            bool unicode_keys = (argc >= 3 && std::string(argv[2]) == "--unicode-keys");
            std::cout << wutong::dcbor_hex_to_jcs(input, unicode_keys);
            return 0;
        }
        if (argc == 3 && std::string(argv[1]) == "--verify") {
            bool ok = wutong::verify_signed_envelope(input, argv[2]);
            if (ok) {
                std::cout << "OK";
                return 0;
            }
            std::cout << "FAIL";
            return 1;
        }
        if (argc == 3 && std::string(argv[1]) == "--verify-cbor") {
            bool ok = wutong::verify_signed_cbor_envelope(input, argv[2]);
            if (ok) {
                std::cout << "OK";
                return 0;
            }
            std::cout << "FAIL";
            return 1;
        }
        if (argc == 3 && std::string(argv[1]) == "--verify-raw-cbor-hex") {
            bool ok = wutong::verify_raw_cbor_hex_envelope(input, argv[2]);
            if (ok) {
                std::cout << "OK";
                return 0;
            }
            std::cout << "FAIL";
            return 1;
        }
        std::cerr << "Usage: wutong_verify_wire [--jcs [--unicode-keys] | --dcbor-hex [--unicode-keys] | --dcbor-decode-hex [--unicode-keys] | --verify <pubkey_hex> | --verify-cbor <pubkey_hex> | --verify-raw-cbor-hex <pubkey_hex>]\n";
        return 2;
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
