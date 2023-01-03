#include <eosio/vm/backend.hpp>
#include <eosio/vm/error_codes.hpp>

#include "wasm/wasm_context_interface.hpp"
#include "wasm/datastream.hpp"
#include "wasm/types/uint128.hpp"
#include "wasm/wasm_constants.hpp"
#include "wasm/wasm_runtime.hpp"
#include "wasm/wasm_interface.hpp"
#include "wasm/wasm_variant.hpp"

#include "wasm/exception/exceptions.hpp"
#include "wasm/contract_tools.hpp"
#include "wasm/wasm_context.hpp"
#include "eosio/vm/watchdog.hpp"

using namespace eosio;
using namespace eosio::vm;



namespace wasm {
    using backend_validate_t = backend<wasm::wasm_context_interface, vm::interpreter>;
    using rhf_t              = eosio::vm::registered_host_functions<wasm_context_interface>;


    std::shared_ptr <wasm_runtime_interface>& get_runtime_interface(){
        static std::shared_ptr <wasm_runtime_interface> runtime_interface;
        return runtime_interface;
    }

    wasm_interface::wasm_interface() {
        initialize(wasm::vm_type::eos_vm);
    }
    wasm_interface::~wasm_interface() {}


    // 初始化vm_runtime
    void wasm_interface::initialize(vm_type vm) {
        static bool wasm_interface_inited = false;
        if(!wasm_interface_inited){
            wasm_interface_inited = true;

            // 走解析器
	        if (vm == wasm::vm_type::eos_vm)
	            get_runtime_interface() = std::make_shared<wasm::wasm_vm_runtime<vm::interpreter>>();
	        else if (vm == wasm::vm_type::eos_vm_jit)
	            get_runtime_interface() = std::make_shared<wasm::wasm_vm_runtime<vm::jit>>();
	        else
	            get_runtime_interface() = std::make_shared<wasm::wasm_vm_runtime<vm::interpreter>>();
    	}

    }

    void wasm_interface::exit() {
        get_runtime_interface()->immediately_exit_currently_running_module();
    }


    std::shared_ptr <wasm_instantiated_module_interface> get_instantiated_backend(const vector <uint8_t> &code) {

        return get_runtime_interface()->instantiate_module((const char*)code.data(), code.size());

    }

    int64_t wasm_interface::execute(const vector <uint8_t> &code, wasm_context_interface *pWasmContext) {
        auto pInstantiated_module = get_instantiated_backend(code);
        return pInstantiated_module->apply(pWasmContext);
    }

    void wasm_interface::validate(const vector <uint8_t> &code) {

        try {
             auto          code_bytes = (uint8_t*)code.data();
             size_t        code_size  = code.size();
             wasm_code_ptr code_ptr(code_bytes, code_size);
             auto bkend               = backend_validate_t(code_ptr, code_size);
             rhf_t::resolve(bkend.get_module());
            //  std::cout << "wasm_interface::validate: resolve end.." << std::endl;
        } catch (vm::exception &e) {
            CHAIN_THROW(wasm_chain::code_parse_exception, e.detail())
        }
        CHAIN_RETHROW_EXCEPTIONS(wasm_chain::code_parse_exception, "wasm code parse exception")

    }

    void wasm_interface::run(const vector <uint8_t> &code, wasm_context_interface *pWasmContext) {

        try {
             auto          code_bytes = (uint8_t*)code.data();
             size_t        code_size  = code.size();
             wasm_code_ptr code_ptr(code_bytes, code_size);
             auto bkend               = backend_validate_t(code_ptr, code_size);


            bkend.set_wasm_allocator(pWasmContext->get_wasm_allocator());
            bkend.initialize();

             rhf_t::resolve(bkend.get_module());
            //  std::cout << "wasm_interface::validate: resolve end.." << std::endl;

            uint64_t i = 1;

            // bkend(pWasmContext, "env", "apply", i, i, wasm::name(action).value );
            auto fn = [&]() {
                const auto &res = bkend.call(
                        pWasmContext, "env", "apply", i, i, wasm::name(pWasmContext->action()).value);
            };


            watchdog wd(pWasmContext->get_max_transaction_duration());
            bkend.timed_run(wd, fn);


        } catch (vm::exception &e) {
            std::cout << "wasm_interface::run exception:" << e.detail() << std::endl;
        }

    }


    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, is_account,               is_account)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, require_auth,               require_auth)
    
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, abort,                   abort)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, wasm_exit,               wasm_exit)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, wasm_assert,             wasm_assert)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, wasm_assert_code,        wasm_assert_code)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, current_time,            current_time)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, read_action_data,        read_action_data)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, action_data_size,        action_data_size)

    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, memcpy,                  memcpy)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, memmove,                 memmove)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, memcmp,                  memcmp)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, memset,                  memset)

    // REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, printn,                  printn)
    // REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, printui,                 printui)
    // REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, printi,                  printi)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, prints,                  prints)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, prints_l,                prints_l)
    // REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, printi128,               printi128)
    // REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, printui128,              printui128)
    // REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, printsf,                 printsf)
    // REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, printdf,                 printdf)

    // //fixme:V4
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, call,                    call)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, get_return,              get_return)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, set_return,              set_return)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, call_with_return,        call_with_return)
    // REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, make_log,                make_log)
    //fixme:V4

    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, db_store,                db_store)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, db_remove,               db_remove)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, db_get,                  db_get)
    REGISTER_WASM_VM_INTRINSIC(wasm_host_methods, env, db_update,               db_update)
    


}//wasm

