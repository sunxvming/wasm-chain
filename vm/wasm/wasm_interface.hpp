#pragma once

#include <vector>
#include <map>
#include "wasm/wasm_context_interface.hpp"
#include "wasm/datastream.hpp"
#include "wasm/wasm_runtime.hpp"
#include "wasm/contract_tools.hpp"
#include "ca/ca_rocksdb.h"
#include "ca/MagicSingleton.h"

#define CHECK_WASM_IN_MEMORY(DATA, LENGTH) \
    if(LENGTH > 0){                        \
        CHAIN_ASSERT( pWasmContext->is_memory_in_wasm_allocator(reinterpret_cast<uint64_t>(DATA) + LENGTH - 1), \
                      wasm_chain::wasm_memory_exception, "access violation" )}

#define CHECK_WASM_DATA_SIZE(LENGTH, DATA_NAME ) \
    CHAIN_ASSERT( LENGTH <= max_wasm_api_data_bytes,                 \
                  wasm_chain::wasm_api_data_size_exceeds_exception,  \
                  "%s size must be <= %ld, but get %ld",              \
                  DATA_NAME, max_wasm_api_data_bytes, LENGTH )

void wasm_code_cache_free();

namespace wasm {
    enum class vm_type {
        eos_vm,
        eos_vm_jit
    };

    class wasm_interface {

    public:

        wasm_interface();
        ~wasm_interface();

    public:
        void initialize(vm_type vm);
        int64_t execute(const vector <uint8_t>& code, wasm_context_interface *pWasmContext);
        void validate(const vector <uint8_t>& code);
        void run(const vector <uint8_t>& code, wasm_context_interface *pWasmContext);
        void exit();

    };

    class wasm_host_methods {

    public:
        wasm_host_methods( wasm_context_interface *pCtx ) {
            pWasmContext = pCtx;
            // print_ignore = !pCtx->contracts_console();
        };

        ~wasm_host_methods() {};

        template<typename T>
        static void AddPrefix( T t, string &key ) {
            std::vector<char> prefix = wasm::pack(t);
                              key    = string((const char *) prefix.data(), prefix.size()) + key;
        }

        // static void AddPrefix( std::string t, string &key ) {
        //     key = t + key;
        // }


        //system
        void abort() {
            CHAIN_ASSERT( false, wasm_chain::abort_called, "abort() called" )
        }

        void wasm_assert( uint32_t test, const void *msg ) {
            CHAIN_ASSERT( test, wasm_chain::wasm_assert_exception, (char *)msg )
        }

        void wasm_assert_message( uint32_t test,  const void *msg, uint32_t msg_len ) {
            if (!test) {
                //CHECK_WASM_IN_MEMORY( msg,     msg_len)
                CHECK_WASM_DATA_SIZE( msg_len, "msg"  )

                std::string str = string((const char *) msg, msg_len);
                CHAIN_ASSERT( false, wasm_chain::wasm_assert_message_exception, str)
            }
        }

        void wasm_assert_code( uint32_t test, uint64_t code ) {
            if (!test) {
                std::ostringstream o;
                o << "err_code:";
                o << code;
                CHAIN_ASSERT(false, wasm_chain::wasm_assert_code_exception, o.str())
            }
        }

        void wasm_exit( int32_t code ){
            //pWasmContext->exit();
        }

        uint64_t current_time() {
            //return static_cast<uint64_t>( context.control.pending_block_time().time_since_epoch().count() );
            //std::cout << "current_time" << std::endl;
            return 0;
            // return pWasmContext->pending_block_time();
        }

        //action
        uint32_t read_action_data( void* data, uint32_t data_len ) {
            uint32_t size = pWasmContext->get_action_data_size();
            if (data_len == 0) return size;

            std::memcpy(data, pWasmContext->get_action_data(), size);
            return size;
        }

         uint32_t action_data_size() {
            auto size = pWasmContext->get_action_data_size();
            // std::cout << "wasm_interface action_data_size:" << size << std::endl;
            return size;
        }


        //memory
        void *memcpy( void *dest, const void *src, int len ) {
            CHAIN_ASSERT( (size_t)(std::abs((ptrdiff_t)dest - (ptrdiff_t)src)) >= len,
                          wasm_chain::overlapping_memory_error,
                          "memcpy can only accept non-aliasing pointers");

            //CHECK_WASM_IN_MEMORY(dest, len)
            //CHECK_WASM_IN_MEMORY(src,  len)

            return (char *) std::memcpy(dest, src, len);
        }

        void *memmove( void *dest, const void *src, int len ) {
            //CHECK_WASM_IN_MEMORY(dest, len)
            //CHECK_WASM_IN_MEMORY(src,  len)

            return (char *) std::memmove(dest, src, len);
        }

        int memcmp( const void *dest, const void *src, int len ) {
            //CHECK_WASM_IN_MEMORY(dest, len)
            //CHECK_WASM_IN_MEMORY(src,  len)

            int ret = std::memcmp(dest, src, len);
            if (ret < 0)
                return -1;
            if (ret > 0)
                return 1;
            return 0;
        }

        void *memset( void *dest, int val, int len ) {
            //CHECK_WASM_IN_MEMORY(dest, len)

            return (char *) std::memset(dest, val, len);
        }

        // void printn( uint64_t val ) {//should be name
        //     if (!print_ignore) {
        //         pWasmContext->console_append(wasm::name(val).to_string());
        //     }
        // }

        // void printui( uint64_t val ) {
        //     if (!print_ignore) {
        //         std::ostringstream o;
        //         o << val;
        //         pWasmContext->console_append(o.str());
        //     }
        // }

        // void printi( int64_t val ) {
        //     if (!print_ignore) {
        //         std::ostringstream o;
        //         o << val;
        //         pWasmContext->console_append(o.str());
        //     }
        // }

        void prints( const void *str ) {
            std::cout << std::string((const char *)str) << std::endl;
        }

        void prints_l( const void *str, uint32_t str_len ) {

            std::cout << std::string((const char *)str, str_len) << std::endl;
        }

        // void printi128( const __int128 &val ) {
        //     if (!print_ignore) {
        //         bool is_negative = (val < 0);
        //         unsigned __int128 val_magnitude;

        //         if (is_negative)
        //             val_magnitude = static_cast<unsigned __int128>(-val); // Works even if val is at the lowest possible value of a int128_t
        //         else
        //             val_magnitude = static_cast<unsigned __int128>(val);

        //         wasm::uint128 v(val_magnitude >> 64, static_cast<uint64_t>(val_magnitude));

        //         if (is_negative) {
        //             pWasmContext->console_append(string("-"));
        //         }

        //         pWasmContext->console_append(string(v));
        //     }
        // }

        // void printui128( const unsigned __int128 &val ) {
        //     if (!print_ignore) {
        //         wasm::uint128 v(val >> 64, static_cast<uint64_t>(val));
        //         pWasmContext->console_append(string(v));
        //     }
        // }

        // void printsf( float val ) {
        //     if (!print_ignore) {
        //         // Assumes float representation on native side is the same as on the WASM side
        //         std::ostringstream o;
        //         o.setf(std::ios::scientific, std::ios::floatfield);
        //         o.precision(std::numeric_limits<float>::digits10);
        //         o << val;

        //         pWasmContext->console_append(o.str());
        //     }
        // }

        // void printdf( double val ) {
        //     if (!print_ignore) {
        //         // Assumes double representation on native side is the same as on the WASM side
        //         std::ostringstream o;
        //         o.setf(std::ios::scientific, std::ios::floatfield);
        //         o.precision(std::numeric_limits<double>::digits10);
        //         o << val;
        //         pWasmContext->console_append(o.str());
        //     }
        // }

        // void emit_result(const char *name, uint32_t name_sz, const char *type, uint32_t type_sz,
        //                     const char *value, uint32_t value_sz) {
        //     pWasmContext->emit_result(string_view(name, name_sz), string_view(type, type_sz),
        //             string_view(value, value_sz));
        // }


        // fixme:V4 support
        uint64_t call(void *data, uint32_t data_len){//return data size
            
            //CHECK_WASM_IN_MEMORY(data,     data_len)
            CHECK_WASM_DATA_SIZE(data_len, "data"  )
            contract_call_t call_info = wasm::unpack<contract_call_t>((const char *) data, data_len);
            return pWasmContext->call(call_info);
        }

        int64_t call_with_return(void *data, uint32_t data_len){//return data in int64_t

            //CHECK_WASM_IN_MEMORY(data,     data_len)
            CHECK_WASM_DATA_SIZE(data_len, "data"  )
            contract_call_t call_info = wasm::unpack<contract_call_t>((const char *) data, data_len);
            return pWasmContext->call_with_return(call_info);

        }

        uint64_t get_return(void *data, uint32_t data_len){

            //CHECK_WASM_IN_MEMORY(data,     data_len)
            CHECK_WASM_DATA_SIZE(data_len, "data"  )

            std::vector<uint8_t> return_value = pWasmContext->get_return();
            uint32_t size = return_value.size();
 
            if(data_len == 0){
                return size;
            }

            auto val_size = data_len > size ? size : data_len;
            std::memcpy(data, return_value.data(), val_size);

            return val_size;
        }

        void set_return(void *data, uint32_t data_len){

            //CHECK_WASM_IN_MEMORY(data,     data_len)
            CHECK_WASM_DATA_SIZE(data_len, "data"  )
            return pWasmContext->set_return(data, data_len);
        }

        // void make_log( uint64_t payer, uint64_t contract, const char* topic, uint32_t topic_len, const char *data, uint32_t data_len ) {

        //     CHECK_WASM_DATA_SIZE(topic_len,  "topic")
        //     CHECK_WASM_DATA_SIZE(data_len,  "data")

        //     string t = string((const char *) topic, topic_len);
        //     string d = string((const char *) data, data_len);

        //     pWasmContext->append_log(payer, contract, t, d);

        // }

        //database
        int32_t db_store( const uint64_t payer, const void *key, uint32_t key_len, const void *val, uint32_t val_len ) {

            //CHECK_WASM_IN_MEMORY(key, key_len)
            //CHECK_WASM_IN_MEMORY(val, val_len)

            CHECK_WASM_DATA_SIZE(key_len, "key"  )
            CHECK_WASM_DATA_SIZE(val_len, "value")

            string k        = string((const char *) key, key_len);
            string v        = string((const char *) val, val_len);
            auto   contract = pWasmContext->contract();

            AddPrefix(contract, k);
            auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
            pRocksDb->writedata(pWasmContext->get_db_transaction(), k, v);
            pWasmContext->update_storage_usage(pWasmContext->get_executor(), k.size() + v.size());
            return 1;
        }

        int32_t db_remove( const uint64_t payer, const void *key, uint32_t key_len ) {

            //CHECK_WASM_IN_MEMORY(key,     key_len)
            CHECK_WASM_DATA_SIZE(key_len, "key"  )

            string k        = string((const char *) key, key_len);
            auto   contract = pWasmContext->contract();
            AddPrefix(contract, k);

       
            return 1;
        }

        int32_t db_get( const void *key, uint32_t key_len, void *val, uint32_t val_len ) {

            //CHECK_WASM_IN_MEMORY(key,     key_len)
            CHECK_WASM_DATA_SIZE(key_len, "key"  )

            string k        = string((const char *) key, key_len);
            auto   contract = pWasmContext->contract();
            AddPrefix(contract, k);
            auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
            string v = pRocksDb->getKey(k);

            auto size    = v.size();
            if (val_len == 0) return size;

            //CHECK_WASM_IN_MEMORY(val,     val_len)
            CHECK_WASM_DATA_SIZE(val_len, "value")

            auto val_size = val_len > size ? size : val_len;
            std::memcpy(val, v.data(), val_size);

            //pWasmContext->update_storage_usage(payer, k.size() + v.size());
            return val_size;
        }

        int32_t db_update( const uint64_t payer, const void *key, uint32_t key_len, const void *val, uint32_t val_len ) {

            //CHECK_WASM_IN_MEMORY(key,     key_len)
            //CHECK_WASM_IN_MEMORY(val,     val_len)
            CHECK_WASM_DATA_SIZE(key_len, "key"  )
            CHECK_WASM_DATA_SIZE(val_len, "value")

            string k        = string((const char *) key, key_len);
            string v        = string((const char *) val, val_len);
            auto   contract = pWasmContext->contract();
            AddPrefix(contract, k);
            MagicSingleton<Rocksdb>::GetInstance()->setKey(k, v);
         
            return 1;
        }


        bool is_account( void* account, uint32_t len ) {
            string acc        = string((const char *) account, len);
            // todo: 增加更严格账号检查
            if(acc.size() == 34)
            {
                return true;
            }else{
                return false;
            }
            // return pWasmContext->is_account(account);
            return false;
        }



        void require_auth( void* account, uint32_t len ) {
            string acc        = string((const char *) account, len);
            pWasmContext->require_auth(acc);
        }


        uint32_t get_maintainer( void* contract, uint32_t len, void* maintainer_data ) {
            if(contract == nullptr || maintainer_data == nullptr)
            {
                return 0;
            }
            string contract_name      = string((const char *) contract, len);
            std::cout << "get_maintainer:contract_name---" << contract_name << std::endl;
            string maintainer = pWasmContext->get_maintainer(contract_name);
            std::cout << "get_maintainer:maintainer---" << maintainer  << std::endl;

            std::memcpy(maintainer_data, maintainer.data(), maintainer.size());
            return maintainer.size();
        }


    public:
        wasm_context_interface *pWasmContext = nullptr;

    private:
        bool print_ignore;

    };



}
