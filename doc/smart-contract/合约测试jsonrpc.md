


## hello.wasm

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

## table_opt.wasm

### add_account
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "execute_contract",
  	"params": {
		"contract": "table_opt.wasm",
		"abi":"table_opt.abi",
		"action": "add_account",
		"params": ["account1",123]
	}
}
```


### 获取数据
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "get_contract_data",
  	"params": {
		"contract": "table_opt",
		"table": "accounts",
		"primary": ""
	}
}
```


## token.wasm

### create
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "execute_contract",
  	"params": {
		"contract": "token.wasm",
		"abi":"token.abi",
		"action": "create",
		"params": ["123rsFMAnEaT3AuPe3d1v9v6Gt7RB6vkYS","uena",10000],
		"executor" : "123rsFMAnEaT3AuPe3d1v9v6Gt7RB6vkYS"
	}
}
```

### issue
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "execute_contract",
  	"params": {
		"contract": "token.wasm",
		"abi":"token.abi",
		"action": "issue",
		"params": ["123rsFMAnEaT3AuPe3d1v9v6Gt7RB6vkYS","uena",1000],
		"executor" : "123rsFMAnEaT3AuPe3d1v9v6Gt7RB6vkYS"
	}
}
```
### transfer
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "execute_contract",
  	"params": {
		"contract": "token.wasm",
		"abi":"token.abi",
		"action": "transfer",
		"params": ["123rsFMAnEaT3AuPe3d1v9v6Gt7RB6vkYS","138dSRmF413TFb7yqmtbaTq75b35U4rdva",100]
	}
}
```


### 获取数据
【token_info】
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "get_contract_data",
  	"params": {
		"contract": "token",
		"table": "token_info",
		"primary": ""
	}
}
```

【余额列表】
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



## database_limit.wasm


### set_data
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "execute_contract", 
  	"params": {
		"contract": "database_limit.wasm",
		"abi":"database_limit.abi",
		"action": "set_data",
		"params": ["key1",1048576,1]
	}
}
```


## 部署合约

### hello.wasm
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

### token.wasm
```
{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "deploy_contract",
    "params": {
        "addr": "1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu",
        "contract": "token.wasm",
        "abi": "token.abi",
        "fee": "0.001"
    }
}
```


## 合约执行

### hello world合约
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

### token合约
#### create
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "execute_contract_rpc",
  	"params": {
        "addr": "1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu",
		"contract": "token.wasm",
		"action": "create",
		"params": ["1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu","uena",10000],
        "fee": "0.001"
	}
}
```

#### issue
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "execute_contract_rpc",
  	"params": {
        "addr": "1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu",
		"contract": "token.wasm",
		"action": "issue",
		"params": ["1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu","uena",1000],
		"fee": "0.001"
	}
}
```
#### transfer
```
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "execute_contract_rpc",
  	"params": {
        "addr": "1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu",
		"contract": "token.wasm",
		"action": "transfer",
		"params": ["1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu","138dSRmF413TFb7yqmtbaTq75b35U4rdva",100],
        "fee": "0.001"
	}
}
```



















