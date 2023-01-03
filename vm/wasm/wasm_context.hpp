#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include <queue>
#include <map>
#include <chrono>

#include "wasm/wasm_interface.hpp"
#include "wasm/datastream.hpp"
#include "eosio/vm/allocator.hpp"
#include "wasm/exception/exceptions.hpp"

using namespace std;

namespace rocksdb {
	class Transaction;
}

namespace wasm {


    enum class ExecuteType {
        file = 0,
        block = 1
    };

    class wasm_context : public wasm_context_interface {

    public:
        using contract_call_t = std::tuple<std::string,std::string,std::string,std::string>;

        wasm_context(ExecuteType exec_type, string contract,  string contract_abi, string contract_raw, string abi_raw, string action, string action_data = "", uint32_t recurse_depth = 0,string executor = "" ):
            exec_type_(exec_type),
            contract_(contract),
            contract_abi_(contract_abi),
            contract_raw_(contract_raw),
            abi_raw_(abi_raw),            
            action_(action), 
            action_data_(action_data),
            recurse_depth_(recurse_depth),
            executor_(executor) 
        {
        };

        ~wasm_context();


    public:
        void initialize();
    public:

        std::string    contract() { return contract_; }
        std::string    action()   { return action_;   }
        
        const char* get_action_data();
        uint32_t    get_action_data_size();

        vm::wasm_allocator* get_wasm_allocator() { return &wasm_alloc; }
        std::chrono::milliseconds get_max_transaction_duration() { return std::chrono::milliseconds(wasm::max_wasm_execute_time_infinite); }

        bool get_code(const std::string& contract, std::vector <uint8_t> &code);
        int64_t execute();
        uint64_t call(contract_call_t call_info);
        int64_t call_with_return(contract_call_t call_info);
        void set_return(void *data, uint32_t data_len);
        std::vector<uint8_t> get_return();
        void set_executor(std::string executor)
        {
            executor_ = executor;
        }
        std::string get_executor()
        {
            return executor_;
        }
        std::string get_maintainer(std::string contract_name);
        void require_auth(std::string account);
        void update_storage_usage( const std::string& account, const int64_t& size_in_bytes);
        rocksdb::Transaction* get_db_transaction();
    public:
        std::string       executor_;
        std::string       contract_;
        std::string       contract_abi_;
        std::string       contract_raw_;
        std::string       abi_raw_;
        std::string       action_;
        std::string       action_data_;
        wasm::wasm_interface        wasmif;
        vm::wasm_allocator          wasm_alloc;
        uint32_t                       recurse_depth_;
        vector<uint8_t>             the_last_return_buffer;
        int64_t           db_use_size  = 0;

        ExecuteType       exec_type_;

    private:
        rocksdb::Transaction *  db_transaction = NULL; 

    };
}
