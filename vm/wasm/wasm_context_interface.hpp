#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <chrono>

#include "wasm/wasm_constants.hpp"
#include "eosio/vm/allocator.hpp"

using namespace eosio;
using namespace eosio::vm;
using namespace std;

namespace rocksdb {
	class Transaction;
}

namespace wasm {

    using contract_call_t = std::tuple<std::string,std::string,std::string,std::string>;
    class wasm_context_interface {

    public:
        wasm_context_interface()  {}
        ~wasm_context_interface() {}

    public:
        virtual std::string contract() = 0;
        virtual std::string action  () = 0;
        virtual const char* get_action_data     () = 0;
        virtual uint32_t    get_action_data_size() = 0;

        virtual std::chrono::milliseconds get_max_transaction_duration() = 0;
        virtual vm::wasm_allocator*   get_wasm_allocator()   = 0;
        virtual uint64_t call(contract_call_t call_info) = 0;
        virtual int64_t call_with_return(contract_call_t call_info) = 0;
        virtual void set_return(void *data, uint32_t data_len) = 0;
        virtual std::vector<uint8_t> get_return() = 0;

        virtual std::string get_maintainer(std::string contract_name) = 0;
        virtual void require_auth(std::string account) = 0;
        virtual void update_storage_usage( const std::string& account, const int64_t& size_in_bytes) = 0;
        virtual std::string get_executor() = 0;
        virtual rocksdb::Transaction* get_db_transaction() = 0;
    };

}