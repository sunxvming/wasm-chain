#define XCTEST

#include <gtest/gtest.h>
#include "wasm/datastream.hpp"






TEST(datastream,int)
{

    char buf[128];
    wasm::datastream<char *> ds( buf, sizeof(buf) );
    int i1 = 123;
    ds << i1;
    int i2;
    ds.seekp(0);
    ds >> i2;

    EXPECT_EQ(i1, i2);
}
