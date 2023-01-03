#include <string>
#include<fstream>


#include "wasm/contract_tools.hpp"
#include "wasm/datastream.hpp"
#include "wasm/abi_serializer.hpp"
#include "wasm/types/name.hpp"
#include "wasm/types/asset.hpp"
#include "wasm/types/regid.hpp"
#include "wasm/wasm_constants.hpp"
#include "wasm/exception/exceptions.hpp"
#include "wasm/wasm_interface.hpp"

namespace wasm {

using namespace std;


void read_file_limit(const string& path, string& data, uint64_t max_size){

    CHAIN_ASSERT( path.size() > 0, wasm_chain::file_read_exception, "file name is missing")

    char byte;
    ifstream f(path, ios::binary);
    CHAIN_ASSERT( f.is_open() , wasm_chain::file_not_found_exception, "file '%s' not found, it must be file name with full path", path)

    streampos pos = f.tellg();
    f.seekg(0, ios::end);
    size_t size = f.tellg();

    CHAIN_ASSERT( size != 0,        wasm_chain::file_read_exception, "file is empty")
    CHAIN_ASSERT( size <= max_size, wasm_chain::file_read_exception,
                  "file is larger than max limited '%d' bytes", MAX_WASM_CONTRACT_CODE_BYTES)
    //if (size == 0 || size > max_size) return false;
    f.seekg(pos);
    while (f.get(byte)) data.push_back(byte);
}


void read_and_validate_code(const string& path, string& code) {
    read_file_limit(path, code, MAX_WASM_CONTRACT_CODE_BYTES);

    vector <uint8_t> c;
    c.insert(c.begin(), code.begin(), code.end());
    wasm_interface wasmif;
    wasmif.validate(c);

}



void run_wasm(const string& path, const string& action) {
    string code;
    read_file_limit(path, code, MAX_WASM_CONTRACT_CODE_BYTES);

    vector <uint8_t> c;
    c.insert(c.begin(), code.begin(), code.end());
    wasm_interface wasmif;
    // wasmif.run(c, action);

}

void read_and_validate_abi(const string& abi_file, string& abi){

    read_file_limit(abi_file, abi, MAX_WASM_CONTRACT_ABI_BYTES);
    json_spirit::Value abi_json;
    json_spirit::read_string(abi, abi_json);

    abi_def abi_struct;
    from_variant(abi_json, abi_struct);
    wasm::abi_serializer abis(abi_struct, max_serialization_time);//validate in abi_serializer constructor

    std::vector<char> abi_bytes = wasm::pack<wasm::abi_def>(abi_struct);
    abi                         = string(abi_bytes.begin(), abi_bytes.end());

}






}