#include "wasm_context.hpp"
//#include "wasm/wasm_native_contract.hpp"
#include "wasm/types/name.hpp"
#include "wasm/wasm_constants.hpp"
#include "wasm/wasm_interface.hpp"
#include "wasm/exception/exceptions.hpp"

#include "wasm/wasm_variant.hpp"
#include "wasm/contract_tools.hpp"
#include "wasm/datastream.hpp"
#include "wasm/abi_serializer.hpp"

#include "ca/ca_rocksdb.h"
#include "ca/MagicSingleton.h"



using namespace std;
// using std::chrono::microseconds;
// using std::chrono::system_clock;
using namespace rocksdb;



namespace wasm {


    wasm_context::~wasm_context() {
        if(db_transaction)
        {
            db_transaction->RollbackToSavePoint();
            delete db_transaction;
        }

        wasm_alloc.free();
    };

    bool wasm_context::get_code(const std::string& contract, std::vector <uint8_t> &code) {
        if(exec_type_ == ExecuteType::file)
        {
            string raw_code;
            read_file_limit(contract, raw_code, MAX_WASM_CONTRACT_CODE_BYTES);

            code.insert(code.begin(), raw_code.begin(), raw_code.end());
            return true;
        }else if(exec_type_ == ExecuteType::block)
        {
            code.insert(code.begin(), contract_raw_.begin(), contract_raw_.end());
            return true;
        }
        return false;
    }


    int64_t wasm_context::execute() {

        CHAIN_ASSERT( recurse_depth_ < wasm::max_recurse_depth, 
                      wasm_chain::resource_limit_exception, "max recursion call" );

        int64_t call_return = -1;
        vector <uint8_t> code;
        if (get_code(contract_, code) && code.size() > 0) {

            auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
            db_transaction = pRocksDb->TransactionInit();
            if( db_transaction == NULL )
            {
                std::cout << "wasm_context execute TransactionInit failed !" << std::endl;
                return 0;
            }

            try {
                call_return = wasmif.execute(code, this);
            } catch (wasm_chain::exception &e) {
                std::cout << "wasm_context::execute have exception=======" << std::endl;
                std::cout << e.to_string() << std::endl;
                return 0;
            } catch(std::exception &e){
                std::cout << "wasm_context::execute have std exception=======" << std::endl;
                std::cout << e.what() << std::endl;  
                return 0;
            }

            if( pRocksDb->TransactionCommit(db_transaction) )
            {
                std::cout << "wasm_context execute  TransactionCommit failed !" << std::endl;
                return 0;
            }

        }else{
            std::cout << "wasm_context get_code error!!" << std::endl;
        }
        return call_return;
    }



    const char* wasm_context::get_action_data(){
        if(exec_type_ == ExecuteType::file)
        {
            std::string  abi;
            read_and_validate_abi (contract_abi_, abi);
            std::vector<char> v_abi(abi.begin(),abi.end());
            std::vector<char> action_data = wasm::abi_serializer::pack(v_abi, action_, action_data_, max_serialization_time);
            return action_data.data();

        }else if(exec_type_ == ExecuteType::block)
        {
            std::string  abi = abi_raw_;
            std::vector<char> v_abi(abi.begin(),abi.end());
            std::vector<char> action_data = wasm::abi_serializer::pack(v_abi, action_, action_data_, max_serialization_time);
            return action_data.data();
        }
        return nullptr;
    }


    uint32_t wasm_context::get_action_data_size() { 
        if(exec_type_ == ExecuteType::file)
        {        
            std::string  abi;
            read_and_validate_abi (contract_abi_, abi);
            std::vector<char> v_abi(abi.begin(),abi.end());
            std::vector<char> action_data = wasm::abi_serializer::pack(v_abi, action_, action_data_, max_serialization_time);
            return action_data.size();
        }else if(exec_type_ == ExecuteType::block)
        {
            std::string  abi = abi_raw_;
            std::vector<char> v_abi(abi.begin(),abi.end());
            std::vector<char> action_data = wasm::abi_serializer::pack(v_abi, action_, action_data_, max_serialization_time);
            return action_data.size();
        } 
        return 0;   
    }


    void wasm_context::set_return(void *data, uint32_t data_len){
        // std::cout << "wasm_context::set_return" << data_len << std::endl;
        std::string data_str((const char *)data, data_len);
        // std::cout << "wasm_context::data_str" << data_str << std::endl;

        the_last_return_buffer = std::vector<uint8_t>(data_str.begin(), data_str.end());

    }

    std::vector<uint8_t> wasm_context::get_return(){
        return the_last_return_buffer;
    }

    uint64_t wasm_context::call(contract_call_t call_info){
        std::string contract;
        std::string contract_abi; 
        std::string action; 
        std::string action_data;
        std::tie(contract, contract_abi, action, action_data) = call_info;
        // std::cout << "wasm_context call=======" << "\n"
        // << "contract:" << contract  << "\n"
        // << "contract_abi:" << contract_abi  << "\n"
        // << "action:" << action  << "\n"
        // << "action_data:" << action_data << "\n"
        // << std::endl; 

        wasm_context cnt( exec_type_, contract, contract_abi, contract_raw_, abi_raw_, action, action_data,  recurse_depth_ + 1);
        cnt.execute();
        the_last_return_buffer = cnt.get_return();
        std::cout << "the_last_return_buffer.size():" << the_last_return_buffer.size() << std::endl;
        return the_last_return_buffer.size() ;
    }

    int64_t wasm_context::call_with_return(contract_call_t call_info){

        std::string contract;
        std::string contract_abi; 
        std::string action; 
        std::string action_data;
        std::tie(contract, contract_abi, action, action_data) = call_info;
        // std::cout << "wasm_context call_with_return======="<< "\n"
        // << "contract:" << contract << "\n"
        // << "contract_abi:" << contract_abi << "\n"
        // << "action:" << action << "\n"
        // << "action_data:" << action_data << "\n"
        // << std::endl; 

        wasm_context cnt( exec_type_, contract, contract_abi,  contract_raw_, abi_raw_,  action, action_data, recurse_depth_ + 1);
        return cnt.execute();

    }


    std::string wasm_context::get_maintainer(std::string contract_name) {
        std::string maintainter = executor_; 
        return maintainter;
    }

    void wasm_context::require_auth(std::string account){
        if(account != get_maintainer(contract_))
        {
             CHAIN_ASSERT(false, wasm_chain::missing_auth_exception, "missing authority of %s", account);
        }
    }


    void wasm_context::update_storage_usage( const std::string& account, const int64_t& size_in_bytes){
        db_use_size += size_in_bytes;
        
        CHAIN_ASSERT(db_use_size <= wasm::max_execute_db_size, wasm_chain::resource_limit_exception, "%s use db size over max_execute_db_size", account);

    }

    Transaction* wasm_context::get_db_transaction(){
        return db_transaction;    
    }

}