
## 一、合约开发工具
- [x] wasm-cdt工具编译和安装
- [x] wasm-cdt目录结构
- [x] wasm-cdt工具的使用
- [x] 用wasm-cdt编译c++合约代码
- [x] c++智能合约的写法
- [x] 合约中入口函数和合约方法的分发


## 二、合约执行层

### 合约约束
- [x] 合约文件大小限制
- [x] abi内容大小限制
- [x] 合约执行时间
- [x] 合约分配内存限制
- [x] 合约数据库操作单条key、value所占空间的大小限制
- [x] 单个合约数据库空间资源大小的限制
- [x] 多合约调用的最深层次

### 执行合约
- [x] 使用jsonrpc读取并执行本地文件合约
    ```
    {
      "jsonrpc": "2.0",
      "id": "1",
      "method": "execute_contract",
        "params": {
            "contract": "hello.wasm",
            "abi":"hello.abi",
            "action": "hi",
            "params": ["abc",123]
        }
    }
    ```
- [x] 创建合约执行上下文 wasm_context
- [x] 调用eos-vm执行合约
- [x] 合约中如何调用自定义方法
    - [x] 打印操作
    - [x] 数据库操作								
        - [x] 读取数据									
        - [x] 写入数据
        - [x] 数据库删除
        - [x] 数据库更新
- [x] 合约的相互调用
- [x] 获取合约执行的返回值
    ```
    实现方式
    一：通过wasm_context上下文对象传递函数返回值
        特点：
            caller和callee通过一段buff来传递返回值，返回的类型可以自己设置
        执行流程
            1.caller合约中通过传入[合约地址、abi、调用方法、调用参数]调用call方法来进行调用callee合约
            2.虚拟机中注册自定义的call方法来实现合约的调用逻辑
                在call方法中创建callee wasm_context对象并执行callee合约
            3.在callee合约中通过调用set_return(),来设置callee wasm_context的the_last_return_buffer    
            4.caller的wasm_context获取callee的the_last_return_buffer    
            5.caller合约中通过调用get_return()来获取callee的返回值
                wasm_interface中get_return调用wasm_context::get_return来设置合约的的返回值为the_last_return_buffer    
    二：通过直接调用传递返回值
        特点：
            返回值只支持int64_t
    ```


## 三、合约逻辑层
- [x] 合约部署		
    ```							
    1.jsonrpc接口调用具体的合约部署方法									
        参数：wasm文件地址、abi文件地址									
        合约部署方法的内容主要是创建交易体																	
    2.创建交易体时把wasm合约和abi文件写入交易体中									
    3.广播签名																	
    4.建块时逻辑    									
        根据交易类型进行处理																		
    5.块写入数据库  																
        对合约和abi根据合约地址进行索引      									
    ```
- [x] 执行合约
    ```
    1.jsonrpc接口调用具体的合约执行方法									
        参数：合约地址、 合约方法、合约方法对应的参数									
        合约执行方法的内容就是创建执行合约的交易体  									
    2.创建交易体  																	
        将执行合约相关的参数写入相应的交易体	
    3.广播签名    
    4.创建块时逻辑									 									
        执行合约									
            查找合约、abi文件									
            读取合约方法、参数									
            调用【合约执行层】执行合约,其中合约的执行者参数为交易的发起者									
    5.块写入数据库  																		
    ```       
- [x] 查询合约
    ``` 
    jsonrpc接口
    method：get_contract_data
    params：contract、table、primary							
    result：合约的table列表
    实现
        根据 合约地址 + table名 + primay 按前缀进行查询
        查找后的结果反序列化成相应的合约中的结构
        获取合约abi
        根据abi反序列化成json	
    ```
- [x] 文档
    - [智能合约jsonrpc接口文档](智能合约jsonrpc接口.md)
            
## 四、测试合约
- [x] hello world合约	
	
   文件：hello.wasm
   功能：
       传入string类型参数、int类型参数，并进行打印
- [x] 数据库存取合约	

   文件：database.wasm
   功能：
       1.把指定数据存入数据库
       2.根据指定key从数据库中取出数据
- [x] 合约table和数据库映射合约(单索引)

   文件：table_opt.wasm
   功能：
       合约table的增删改查和数据库的操作进行映射
           add_account
               向数据库添加数据
           get_account
               从数据库获取数据

- [x] 合约table和数据库映射合约(多索引)

   文件：index.wasm
   功能：
       用带多个索引的index_table类模板支持数据增删改查
       根据主索引取数据
       根据次索引取数据

- [x] 合约执行时间测试合约

   文件：print_per_second.wasm
   功能：
       合约功能为不停向屏幕输出，用于测试限制合约执行时间的功能,执行超过限制时间后合约停止

- [x] 内存申请合约

   文件：alloc_mem.wasm
   功能：
       合约功能为调用malloc函数请求固定大小的内存10M，用于测试限制合约反复执行时是否有内存泄漏问题

- [x] 返回值测试合约

   文件：return_value.wasm
   功能：
       合约内不同的方法返回不同类型的值，用于测试合约方法的返回值

- [x] 调用其他合约的合约

   文件：call.wasm
   功能：
       在当前合约中调用return_value.wasm合约的方法,并获取返回值
- [x] 递归调用合约

   文件：recursion_call.wasm
   功能：
       合约中通过call方法来递归的调用自己，测试递归情况下的合约执行时间
- [x] 单次执行合约数据库最大开辟空间测试合约

   文件：database_limit.wasm    
   功能：
       合约中通过调用数据库写入方法，来写入执行大小的数据，用以测试合约单次最大写入数据库的数据量     
- [x] token发行测试合约

   功能：实现发行token的功能
   合约方法：
       创建token
           create  (string issuer, string token_name, uint64_t maximum_supply);
       token数量增发
           issue( string issuer, string token_name, uint64_t quantity);
       token转账
           transfer(string from, string to, uint64_t quantity);





## 五、相关链接
- [智能合约入门.md](doc/smart-contract/智能合约入门.md)
- [智能合约功能.txt](doc/smart-contract/智能合约功能.txt)
- [智能合约模块源码说明.md](doc/smart-contract/智能合约模块源码说明.md)
- [合约测试jsonrpc.md](doc/smart-contract/合约测试jsonrpc.md)
- [eos-vm github源码](https://github.com/EOSIO/eos-vm)
- [维基链github源码](https://github.com/WaykiChain/WaykiChain)
- [维基链wasm-cdt合约开发工具源码](https://github.com/WaykiChain/wicc-wasm-cdt)



