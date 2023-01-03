#define XCTEST

#include <gtest/gtest.h>
#include <string>
#include <chrono>
#include <thread>

#include "wasm/datastream.hpp"

#include "wasm/contract_tools.hpp"
#include "wasm/wasm_context.hpp"
#include "wasm/wasm_interface.hpp"



TEST(contract_tools,read_and_validate_code)
{
    using namespace wasm;

    string code, abi;
    read_and_validate_code("hello.wasm", code);
    EXPECT_EQ(1, 1);
}



TEST(contract_tools,read_and_run_code)
{
    using namespace wasm;
    // run_wasm("hello.wasm", "hi");
}



TEST(wasm_context,db_prefixkey)
{
    using namespace wasm;

    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();


    pRocksDb->setKey("key1", "value1");
    pRocksDb->setKey("abc2", "value2");
    pRocksDb->setKey("abc3", "value3");
    pRocksDb->setKey("abc4", "value4");
    pRocksDb->setKey("abc1", "value1");
    pRocksDb->setKey("key2", "value2");
    pRocksDb->setKey("key3", "value3");
    pRocksDb->setKey("key4", "value4");



    std::map<std::string, std::string> res = pRocksDb->prefix_key("key");
    for(const auto& i:res)
    {
        std::cout << i.first << ":" << i.second << std::endl;
    }

    MagicSingleton<Rocksdb>::DesInstance();


}



TEST(contract,hello)
{
    using namespace wasm;

    wasm_context cnt("hello.wasm", "hello.abi", "hi", R"(["abc",123])");
    cnt.execute();
}


TEST(contract,database)
{
    using namespace wasm;

    wasm_context cnt("database.wasm", "database.abi", "set_data", R"(["key1","value1"])");
    cnt.execute();

    wasm_context cnt2("database.wasm", "database.abi", "get_data", R"(["key1"])");
    cnt2.execute();

}




TEST(contract,table_opt)
{
    using namespace wasm;

    wasm_context cnt("table_opt.wasm", "table_opt.abi", "add_account", R"(["account1",100])");
    cnt.execute();

    wasm_context cnt2("table_opt.wasm", "table_opt.abi", "get_account", R"(["account1"])");
    cnt2.execute();

}



TEST(contract,multi_index)
{
    using namespace wasm;

    {
        wasm_context cnt("index.wasm", "index.abi", "add", R"([1,"user1", 100])");
        cnt.execute();
    }


    {
        wasm_context cnt("index.wasm", "index.abi", "add", R"([2,"user2", 200])");
        cnt.execute();
    }


    {
        wasm_context cnt("index.wasm", "index.abi", "add", R"([3,"user3", 300])");
        cnt.execute();
    }


    {
        wasm_context cnt("index.wasm", "index.abi", "add", R"([4,"user4", 300])");
        cnt.execute();
    }

    {
        wasm_context cnt("index.wasm", "index.abi", "get", R"([1,"user1", 100])");
        cnt.execute();
    }


    {
        wasm_context cnt("index.wasm", "index.abi", "get", R"([4,"user4", 300])");
        cnt.execute();
    }

}




// TEST(contract,print_per_second)
// {
//     using namespace wasm;

//     {
//         wasm_context cnt("print_per_second.wasm", "print_per_second.abi", "execute", R"([])");
//         cnt.execute();
//     }
// }

//测试合约内存分配后是否一直增长
TEST(contract,alloc_mem)
{
    using namespace wasm;

    // for(;;)
    // {
    //     wasm_context cnt("alloc_mem.wasm", "alloc_mem.abi", "execute", R"([])");
    //     cnt.execute();
    //     std::this_thread::sleep_for(20ms);
    // }
}



TEST(contract,call)
{
    using namespace wasm;

    {
        wasm_context cnt("call.wasm", "call.abi", "get_ret", R"([])");
        cnt.execute();
    }

    {
        wasm_context cnt("call.wasm", "call.abi", "get_ret2", R"([])");
        cnt.execute();
    }    
}


TEST(contract,recursion_call)
{
    using namespace wasm;

    {
        wasm_context cnt("recursion_call.wasm", "recursion_call.abi", "exec", R"([0])");
        cnt.execute();
    }  
}