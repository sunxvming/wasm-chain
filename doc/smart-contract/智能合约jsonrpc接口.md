## 一、部署合约

### 请求  
```
{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "deploy_contract",
    "params": {
        "addr": "1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu",
        "contract": "hello.wasm",
        "abi": "hello.abi",
        "fee": "0.001"
    }
}
```


### 返回
```
{
    "id": "1",
    "jsonrpc": "2.0",
    "result": {
        "tx_hash": "ead2bd4a26dfd2dd94535545968b81bc7d8f77976d80bc1197641e2bfa3486d2"
    }
}
```  

### 字段说明
``` 
请求
addr       部署合约地址
contract   合约文件
abi        合约abi文件
fee        交易费
返回
tx_hash    交易体的hash值     
```




## 二、执行合约

### 请求
```
{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "execute_contract_rpc",
    "params": {
        "addr": "1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu",
        "contract": "hello.wasm",
        "action" : "hi",
        "params": ["abc",123],
        "fee": "0.001"
    }
}
```

### 返回
```
{
    "id": "1",
    "jsonrpc": "2.0",
    "result": {
        "tx_hash": "b1daf3dc7ca7af98ab43d1f8381277334fa1de7a75b0ab14389502070b597678"
    }
}
```


### 字段说明
``` 
请求
addr       部署合约地址
contract   合约文件
action     合约中所调用的方法
params     合约中所调用方法传入的参数
fee        交易费
返回
tx_hash    交易体的hash值     
```


## 三、查看合约数据
### 请求
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "get_contract_data",
  	"params": {
		"contract": "token",
		"table": "accounts",
		"primary": ""
	}
}
```

### 返回
```
{
    "id": "1",
    "jsonrpc": "2.0",
    "result": {
        "data": [
            "{\"owner\":\"1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu\",\"balance\":1000}"
        ]
    }
}
```


### 字段说明
``` 
请求
addr       部署合约地址
contract   合约名称
table      合约中所对应的table名
primary    查询合约table的索引
fee        交易费
返回
data       合约数据的列表    
```