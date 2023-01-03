#define XCTEST

#include <gtest/gtest.h>
#include <string>

#include "wasm/datastream.hpp"

#include "wasm/contract_tools.hpp"
#include "wasm/abi_serializer.hpp"



TEST(abi,hello_param)
{
    using namespace wasm;

    std::string  abi;
    read_and_validate_abi ("hello.abi", abi);
    std::vector<char> v_abi(abi.begin(),abi.end());
    std::string param = R"(["abc",123])";
    std::vector<char> action_data = wasm::abi_serializer::pack(v_abi, "hi", param, max_serialization_time);


    std::tuple<std::string, int32_t> args;
    datastream<const char*> ds((char*)action_data.data(), action_data.size());
    ds >> args;  

    std::string s = std::get<0>(args);
    int32_t i = std::get<1>(args);
    std::cout << "s:" << s << " i:" << i << std::endl;

    EXPECT_STREQ(s.c_str(), "abc");
    EXPECT_EQ(i, 123);
    
}
