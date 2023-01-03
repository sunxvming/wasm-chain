#pragma once

#include <string>
#include <iostream>

enum VMType : uint8_t {
    NULL_VM     = 0,
    LUA_VM      = 1,
    WASM_VM     = 2,
    EVM         = 3
};

static const uint32_t MAX_WASM_CONTRACT_CODE_BYTES          = 1024 * 1024;      // 1 MB max for wasm contract code bytes
static const uint32_t MAX_WASM_CONTRACT_ABI_BYTES           = 1024 * 1024;      // 1 MB max for wasm contract abi bytes

#define MAKE_BENCHMARK(msg) std::cout << msg << std::endl

using uint256   = uint32_t;


namespace wasm {
    using std::string;

    void read_file_limit(const string& path, string& data, uint64_t max_size);
    void read_and_validate_abi(const string& abi_file, string& abi);
    void read_and_validate_code(const string& path, string& code);


    void run_wasm(const string& path, const string& action);

}