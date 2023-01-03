cmake_minimum_required(VERSION 3.0)

project (ebpc) 

set(CMAKE_CXX_STANDARD 17)


set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(use-gold-linker)
include(use-ccache)


# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold")


# 编译类型相关 Debug or Release
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -rdynamic")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -rdynamic")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -rdynamic")
set(CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -rdynamic")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

message("CMAKE_BUILD_TYPE is:${CMAKE_BUILD_TYPE}")

# message("CMAKE_CXX_FLAGS_DEBUG :================")
# message(${CMAKE_CXX_FLAGS_DEBUG})

# message("CMAKE_CXX_FLAGS_RELEASE  :================")
# message(${CMAKE_CXX_FLAGS_RELEASE})

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR "CMAKE_BUILD_TYPE must be Debug or Release!!!")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    execute_process(COMMAND sed -i "s/g_testflag.*;/g_testflag = 1;/g" ${CMAKE_SOURCE_DIR}/common/global.cpp)
endif()


if(CMAKE_BUILD_TYPE STREQUAL "Release")
    execute_process(COMMAND sed -i "s/g_testflag.*;/g_testflag = 0;/g" ${CMAKE_SOURCE_DIR}/common/global.cpp)
endif()



add_definitions(-Wno-builtin-macro-redefined)

# 打印编译时间
set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time")
set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CMAKE_COMMAND} -E time")

set(CXX_FLAGS
        -Wall
        )
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -save-temps")

# 定义工程根目录; CMAKE_SOURCE_DIR为内建变量，表示工程根目录的CMakeLists.txt文件路径
SET(ROOT_DIR ${CMAKE_SOURCE_DIR})



execute_process(COMMAND sh ${ROOT_DIR}/make_depend.sh)


# 编译那些源码
file(GLOB SOURCES 
    "*.cpp"
    "include/*.cpp" 
    "utils/*.cpp"
    "utils/json/*.cpp"
    "utils/*.c"
    "ca/*.cpp"
    "net/*.cpp"
    "common/*.cpp"
    "main/*.cpp"
    "proto/*.cc"
    "vm/wasm/*.cpp"
     "vm/wasm/types/*.cpp"
     "vm/wasm/exception/*.cpp"
     "log/*.cpp"
    )

file(GLOB_RECURSE MAIN_FILE entry.cpp)
list(REMOVE_ITEM SOURCES ${MAIN_FILE})

# message("source:================")
# message(${SOURCES})
# message("MAIN_FILE:================")
# message(${MAIN_FILE})

# test的源码
file(GLOB_RECURSE TEST_SOURCE tests/*.cpp)
message(${TEST_SOURCE})




# 编译目标
add_executable(${PROJECT_NAME}  ${MAIN_FILE} ${SOURCES})
include (utils)
redefine_file_macro(${PROJECT_NAME})


set(EXECUTABLE_OUTPUT_PATH bin)
# 包含路径
include_directories("${ROOT_DIR}/")
include_directories("${ROOT_DIR}/ca")
include_directories("${ROOT_DIR}/vm")
include_directories("${ROOT_DIR}/include")
include_directories("${ROOT_DIR}/rocksdb/include")
include_directories("${ROOT_DIR}/protobuf/src")
include_directories("${ROOT_DIR}/proto")
#增加eos vm路径
include_directories("${ROOT_DIR}/vm/wasm/eos-vm/include")
include_directories("${ROOT_DIR}/spdlog/include")


target_compile_definitions(${PROJECT_NAME} PUBLIC "WAVM_API=")


# 添加动态库
target_link_libraries(${PROJECT_NAME}  dl)
target_link_libraries(${PROJECT_NAME}  z)
#target_link_libraries(${PROJECT_NAME}  bz2)
target_link_libraries(${PROJECT_NAME} "pthread" ) 



# 添加外部静态
add_library(crypto STATIC IMPORTED)
set_property(TARGET crypto PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/crypto/cryptopp/libcryptopp.a)
target_link_libraries(${PROJECT_NAME}  crypto )


add_library(rocksdb STATIC IMPORTED)
set_property(TARGET rocksdb PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/rocksdb/librocksdb.a)
target_link_libraries(${PROJECT_NAME}  rocksdb )


add_library(protobuf STATIC IMPORTED)
set_property(TARGET protobuf PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/protobuf/src/.libs/libprotobuf.a)
target_link_libraries(${PROJECT_NAME}  protobuf )

add_library(spdlog STATIC IMPORTED)
set_property(TARGET spdlog PROPERTY IMPORTED_LOCATION ${ROOT_DIR}/spdlog/libspdlog.a)
target_link_libraries(${PROJECT_NAME}  spdlog )


find_package(GTest)
if(GTEST_FOUND)
    # GTEST_INCLUDE_DIRS:/usr/local/include
    # message("GTEST_INCLUDE_DIRS:${GTEST_INCLUDE_DIRS}")
    include_directories(${GTEST_INCLUDE_DIRS})
    add_executable(test EXCLUDE_FROM_ALL ${SOURCES} ${TEST_SOURCE})
    
    # GTEST_BOTH_LIBRARIES:/usr/local/lib64/libgtest.a;/usr/local/lib64/libgtest_main.a
    message("GTEST_BOTH_LIBRARIES:${GTEST_BOTH_LIBRARIES}")
    # CMAKE_THREAD_LIBS_INIT:-lpthread, gtest依赖于线程库
    message("CMAKE_THREAD_LIBS_INIT:${CMAKE_THREAD_LIBS_INIT}")

    target_link_libraries(test ${GTEST_BOTH_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

    target_link_libraries(test  dl)
    target_link_libraries(test  z)
    target_link_libraries(test  bz2)
    target_link_libraries(test  pthread ) 
    target_link_libraries(test  crypto )
    target_link_libraries(test  rocksdb )
    target_link_libraries(test  protobuf )
    target_link_libraries(test  spdlog)

endif(GTEST_FOUND)



ADD_CUSTOM_COMMAND(TARGET ${PROJECT_NAME}
    POST_BUILD 
    COMMAND sh ${CMAKE_SOURCE_DIR}/gen_version_info.sh
)

# install(CODE "execute_process(COMMAND sh ${CMAKE_SOURCE_DIR}/gen_version_info.sh)")
