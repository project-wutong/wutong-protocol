// SPDX-License-Identifier: AGPL-3.0-only
#include "wutong/core.hpp"
#include <iostream>
int main(int argc,char** argv) {
    if(argc!=2) {std::cerr<<"Usage: wutong_digest <file>\n";return 2;}
    try{std::cout<<wutong::sha256_hex(wutong::read_bytes(argv[1]))<<'\n';return 0;}
    catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}
}
