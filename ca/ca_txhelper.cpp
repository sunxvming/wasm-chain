
#include "ca_blockpool.h"
#include "ca_console.h"

#include "../include/logging.h"
#include "ca_transaction.h"
#include <algorithm>
#include <iterator>
#include <pthread.h>
#include "ca_global.h"
#include "ca_hexcode.h"
#include "ca_rocksdb.h"
#include "MagicSingleton.h"
#include "../include/ScopeGuard.h"
#include "ca_txhelper.h"
#include "../utils/string_util.h"
#include "../utils/time_util.h"
#include "../utils/json.hpp"
#include "ca_base64.h"
#include "ca_message.h"
#include "ca_txvincache.h"
#include "../utils/base64.h"
#include "ca_rocksdb.h"

#include <google/protobuf/util/json_util.h>
#include "wasm/wasm_context.hpp"


using namespace google::protobuf;

std::vector<std::string> TxHelper::GetTxOwner(const std::string tx_hash)
{
	std::vector<std::string> address;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(CreateTxMessage) TransactionInit failed !");
		return address;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	std::string strTxRaw;
	if (pRocksDb->GetTransactionByHash(txn, tx_hash, strTxRaw) != 0)
	{
		return address;
	}

	CTransaction Tx;
	Tx.ParseFromString(strTxRaw);
	
	return GetTxOwner(Tx);
}

std::string TxHelper::GetTxOwnerStr(const std::string tx_hash)
{
	std::vector<std::string> address = GetTxOwner(tx_hash);
	return StringUtil::concat(address, "_");
}

std::vector<std::string> TxHelper::GetTxOwner(const CTransaction & tx)
{
	std::vector<std::string> address;
	for (int i = 0; i < tx.vin_size(); i++)
	{
		CTxin txin = tx.vin(i);
		auto pub = txin.mutable_scriptsig()->pub();
		std::string addr = GetBase58Addr(pub); 
		auto res = std::find(std::begin(address), std::end(address), addr);
		if (res == std::end(address)) 
		{
			address.push_back(addr);
		}
	}

	return address;	
}

std::string TxHelper::GetTxOwnerStr(const CTransaction & tx)
{
	std::vector<std::string> address = GetTxOwner(tx);
	return StringUtil::concat(address, "_");
}

std::vector<std::string> TxHelper::GetUtxosByAddresses(std::vector<std::string> addresses)
{
	std::vector<std::string> vUtxoHashs;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(GetUtxosByAddresses) TransactionInit failed !");
		return vUtxoHashs;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	for(auto& addr:addresses)
	{
		std::vector<std::string> tmp;
		auto db_status = pRocksDb->GetUtxoHashsByAddress(txn, addr, tmp);
		if (db_status != 0) {
			DEBUGLOG("(GetUtxosByAddresses) GetUtxoHashsByAddress:{}", addr);
			return vUtxoHashs;
		}
		std::for_each(tmp.begin(), tmp.end(),
				[&](std::string &s){ s = s + "_" + addr;}
		);		

		vUtxoHashs.insert(vUtxoHashs.end(), tmp.begin(), tmp.end());
	}
	return vUtxoHashs;
}

std::vector<std::string> TxHelper::GetUtxosByTx(const CTransaction & tx)
{
	std::vector<std::string> v1;
	for(int j = 0; j < tx.vin_size(); j++)
	{
		CTxin vin = tx.vin(j);
		std::string hash = vin.prevout().hash();
		
		if(hash.size() > 0)
		{
			v1.push_back(hash + "_" + GetBase58Addr(vin.scriptsig().pub()));
		}
	}
	return v1;
}


uint64_t TxHelper::GetUtxoAmount(std::string tx_hash, std::string address)
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(CreateTxMessage) TransactionInit failed !");
		return 0;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	std::string strTxRaw;
	if (pRocksDb->GetTransactionByHash(txn, tx_hash, strTxRaw) != 0)
	{
		return 0;
	}

	CTransaction tx;
	tx.ParseFromString(strTxRaw);

	uint64_t amount = 0;
	for (int j = 0; j < tx.vout_size(); j++)
	{
		CTxout txout = tx.vout(j);
		if (txout.scriptpubkey() == address)
		{
			amount += txout.value();
		}
	}
	return amount;
}


int TxHelper::CreateTxMessage(const std::vector<std::string> & fromAddr, 
	const std::map<std::string, int64_t> toAddr, 
	uint32_t needVerifyPreHashCount, 
	uint64_t minerFees, 
	CTransaction & outTx,
	bool is_local)
{
	if (fromAddr.size() == 0 || toAddr.size() == 0)
	{
		ERRORLOG("CreateTxMessage fromAddr toAddr ==0");
		return -1;
	}

	std::set<std::string> fromSet;
	std::set<std::string> toSet;
	for (auto & to : toAddr)
	{
		if (to.first != VIRTUAL_ACCOUNT_PLEDGE && ! CheckBase58Addr(to.first))
		{
			ERRORLOG("CreateTxMessage test2");
			return -2;
		}

		toSet.insert(to.first);

		for (auto & from : fromAddr)
		{
			if (! CheckBase58Addr(from))
			{
				ERRORLOG("CreateTxMessage test3");
				return -2;
			}

			fromSet.insert(from);
			if (from == to.first)
			{
				return -2;
			}
		}
	}

	if (fromSet.size() != fromAddr.size() || toSet.size() != toAddr.size())
	{
		ERRORLOG("CreateTxMessage test4");
		return -2;
	}

	if (MagicSingleton<TxVinCache>::GetInstance()->IsConflict(fromAddr))
	{
		ERRORLOG("Pending transaction is in Cache!");
		return -3;
	}

    int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(CreateTxMessage) TransactionInit failed !");
		return -4;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};
	

	uint64_t amount = 0;
	for(auto& i:toAddr)
	{
		amount += i.second;
	}
	amount += ( (needVerifyPreHashCount - 1) * minerFees );

	// 是否需要打包费
	bool bIsNeedPackage = IsNeedPackage(fromAddr);
	
	// 交易发起方支付打包费
	uint64_t publicNodePackageFee = 0;
	if (bIsNeedPackage)
	{
		if ( 0 != pRocksDb->GetDevicePackageFee(publicNodePackageFee) )
		{
			ERRORLOG("CreateTxMessage GetDevicePackageFee failed");
			return -5;
		}

		amount += publicNodePackageFee;
	}

	std::map<std::string, std::vector<std::string>> utxoHashs;
	for(auto& addr:fromAddr)
	{
		std::vector<std::string> tmp;
		db_status = pRocksDb->GetUtxoHashsByAddress(txn, addr, tmp);
		if (db_status != 0) {
			ERRORLOG("CreateTxMessage GetUtxoHashsByAddress");
			return -6;
		}
		utxoHashs[addr] = tmp;
	}

	uint64_t total = 0;
	std::string change_addr;
	std::set<std::string> txowners;
	for(auto& addr:fromAddr)
	{
		for (auto& item : utxoHashs[addr])
		{
			std::string strTxRaw;
			if (pRocksDb->GetTransactionByHash(txn, item, strTxRaw) != 0)
			{
				continue;
			}
			CTransaction utxoTx;
			utxoTx.ParseFromString(strTxRaw);

			for (int i = 0; i < utxoTx.vout_size(); i++)
			{
				CTxout txout = utxoTx.vout(i);
				if(txout.scriptpubkey() == addr)
				{
					txowners.insert(addr);
					change_addr = addr;
					total += txout.value();

					CTxin * txin = outTx.add_vin();
					CTxprevout * prevout = txin->mutable_prevout();
					prevout->set_hash(utxoTx.hash());
					prevout->set_n(utxoTx.n());

					if(is_local)
					{
						std::string strPub;
						g_AccountInfo.GetPubKeyStr(txout.scriptpubkey().c_str(), strPub);
						txin->mutable_scriptsig()->set_pub(strPub);
					}
					else
					{
						txin->mutable_scriptsig()->set_pub(addr);
						DEBUGLOG("CreateTxMessage vin addr:{}", addr);
					}
				}
			}
			if (total >= amount)
			{
				break;
			}
		}
		if (total >= amount)
		{
			break;
		}		
	}
	if (total < amount)
	{
		ERRORLOG("CreateTxMessage total < amount");
		return -7;
	}

	if((uint64_t)minerFees < g_minSignFee || (uint64_t)minerFees > g_maxSignFee)
	{
		return -15;
	}

	for(auto& i:toAddr)
	{
		CTxout * txoutToAddr = outTx.add_vout();
		txoutToAddr->set_scriptpubkey(i.first);
		txoutToAddr->set_value(i.second);
	}
	
	CTxout * txoutFromAddr = outTx.add_vout();
	txoutFromAddr->set_value(total - amount);
	txoutFromAddr->set_scriptpubkey(change_addr);

	uint64_t time = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
	outTx.set_time(time);

	std::string tmpAddr;
	for (auto & addr : txowners)
	{
		tmpAddr += addr;
		tmpAddr += "_";
	}
	
	tmpAddr.erase(tmpAddr.end() -1);
	
	outTx.set_txowner(tmpAddr);

	outTx.set_ip(net_get_self_node_id());

	nlohmann::json extra;
	extra["NeedVerifyPreHashCount"] = needVerifyPreHashCount;
	extra["SignFee"] = minerFees;
	extra["PackageFee"] = publicNodePackageFee;
	extra["TransactionType"] = TXTYPE_TX;
	outTx.set_extra(extra.dump());

	return 0;
}

void TxHelper::DoCreateTx(const std::vector<std::string> & fromAddr, 
	const std::map<std::string, int64_t> toAddr, 
	uint32_t needVerifyPreHashCount, 
	uint64_t gasFee)
{
	if (fromAddr.size() == 0 || toAddr.size() == 0 )
	{
		ERRORLOG("DoCreateTx: fromAddr.size() == 0 || toAddr.size() == 0");
		return; 
	}

	CTransaction outTx;
    int ret = TxHelper::CreateTxMessage(fromAddr,toAddr, needVerifyPreHashCount, gasFee, outTx);
	if(ret != 0)
	{
		ERRORLOG("DoCreateTx: TxHelper::CreateTxMessage error!!");
		return;
	}

	std::vector<std::string> addrs;
	for (int i = 0; i < outTx.vin_size(); i++)
	{
		CTxin * txin = outTx.mutable_vin(i);;
		std::string pub = txin->mutable_scriptsig()->pub();
		txin->clear_scriptsig();
		addrs.push_back(GetBase58Addr(pub));
	}

	std::string serTx = outTx.SerializeAsString();

	size_t encodeLen = serTx.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)serTx.data(), serTx.size(), encode);
	std::string encodeStr( (char *)encode, codeLen );

	std::string encodeStrHash = getsha256hash(encodeStr);

	//签名
	for (int i = 0; i < outTx.vin_size(); i++)
	{
		std::string addr = addrs[i];
		std::string signature;
		std::string strPub;
		g_AccountInfo.Sign(addr.c_str(), encodeStrHash, signature);
		g_AccountInfo.GetPubKeyStr(addr.c_str(), strPub);
		CTxin * txin = outTx.mutable_vin(i);
		txin->mutable_scriptsig()->set_sign(signature);
		txin->mutable_scriptsig()->set_pub(strPub);
	}
	
	serTx = outTx.SerializeAsString();

	TxMsg txMsg;
	txMsg.set_version(getVersion());
	txMsg.set_tx( serTx );
	txMsg.set_txencodehash( encodeStrHash );

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	unsigned int top = 0;
	pRocksDb->GetBlockTop(txn, top);	
	txMsg.set_top(top);

	std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        ERRORLOG("GetBestChainHash return no zero");
        return;
    }
    txMsg.set_prevblkhash(blockHash);	
    txMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));

	auto msg = make_shared<TxMsg>(txMsg);

	std::string txHash;
	int err = DoHandleTx(msg, txHash);
	DEBUGLOG("交易处理结果，ret:{}  txHash：{}", err, txHash);
	
}


int TxHelper::CreateDeployContractMessage(const std::string & addr, 
	const std::string &contract_name,
	const std::string &contract, 
	const std::string &abi, 
	uint32_t needVerifyPreHashCount, 
	uint64_t minerFees, 
	CTransaction & outTx 
	)
{

	if (addr.size() == 0 )
	{
		ERRORLOG("CreateDeployContractMessage addr is empty");
		return -1;
	}

	if (contract.size() == 0 )
	{
		ERRORLOG("CreateDeployContractMessage contract is empty");
		return -1;
	}

	if (abi.size() == 0 )
	{
		ERRORLOG("CreateDeployContractMessage abi is empty");
		return -1;
	}

	std::vector<std::string> fromAddr;
	fromAddr.push_back(addr); 

    int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(CreateDeployContractMessage) TransactionInit failed !");
		return -4;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};
	
	// 支付的燃料费
	uint64_t amount =  (needVerifyPreHashCount - 1) * minerFees;

	// 是否需要打包费
	bool bIsNeedPackage = IsNeedPackage(fromAddr);
	
	// 交易发起方支付打包费
	uint64_t publicNodePackageFee = 0;
	if (bIsNeedPackage)
	{
		if ( 0 != pRocksDb->GetDevicePackageFee(publicNodePackageFee) )
		{
			ERRORLOG("CreateDeployContractMessage GetDevicePackageFee failed");
			return -5;
		}

		amount += publicNodePackageFee;
	}

	std::map<std::string, std::vector<std::string>> utxoHashs;
	for(auto& addr:fromAddr)
	{
		std::vector<std::string> tmp;
		db_status = pRocksDb->GetUtxoHashsByAddress(txn, addr, tmp);
		if (db_status != 0) {
			ERRORLOG("CreateDeployContractMessage GetUtxoHashsByAddress");
			return -6;
		}
		utxoHashs[addr] = tmp;
	}

	uint64_t total = 0;
	std::string change_addr;
	std::set<std::string> txowners;
	for(auto& addr:fromAddr)
	{
		for (auto& item : utxoHashs[addr])
		{
			std::string strTxRaw;
			if (pRocksDb->GetTransactionByHash(txn, item, strTxRaw) != 0)
			{
				continue;
			}
			CTransaction utxoTx;
			utxoTx.ParseFromString(strTxRaw);

			for (int i = 0; i < utxoTx.vout_size(); i++)
			{
				CTxout txout = utxoTx.vout(i);
				if(txout.scriptpubkey() == addr)
				{
					txowners.insert(addr);
					change_addr = addr;
					total += txout.value();

					CTxin * txin = outTx.add_vin();
					CTxprevout * prevout = txin->mutable_prevout();
					prevout->set_hash(utxoTx.hash());
					prevout->set_n(utxoTx.n());

					std::string strPub;
					g_AccountInfo.GetPubKeyStr(txout.scriptpubkey().c_str(), strPub);
					txin->mutable_scriptsig()->set_pub(strPub);
				}
			}
			if (total >= amount)
			{
				break;
			}
		}
		if (total >= amount)
		{
			break;
		}		
	}
	if (total < amount)
	{
		ERRORLOG("CreateDeployContractMessage total < amount");
		return -7;
	}

	if((uint64_t)minerFees < g_minSignFee || (uint64_t)minerFees > g_maxSignFee)
	{
		return -15;
	}
	
	// 设置找零地址
	CTxout * txoutFromAddr = outTx.add_vout();
	txoutFromAddr->set_value(total - amount);
	txoutFromAddr->set_scriptpubkey(change_addr);

	uint64_t time = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
	outTx.set_time(time);

	std::string tmpAddr;
	for (auto & addr : txowners)
	{
		tmpAddr += addr;
		tmpAddr += "_";
	}
	
	tmpAddr.erase(tmpAddr.end() -1);
	
	outTx.set_txowner(tmpAddr);

	outTx.set_ip(net_get_self_node_id());

	nlohmann::json extra;
	extra["NeedVerifyPreHashCount"] = needVerifyPreHashCount;
	extra["SignFee"] = minerFees;
	extra["TransactionType"] = TXTYPE_CONTRACT_DEPLOY;
	extra["PackageFee"] = publicNodePackageFee;

	extra["ContractName"] = contract_name;
	extra["Contract"] = base64Encode(contract);
	extra["Abi"] = base64Encode(abi);

	outTx.set_extra(extra.dump());

	return 0;		


}


void TxHelper::DoDeployContract(const std::string & addr, 
	const std::string &contract_name,
	const std::string &contract, 
	const std::string &abi,
	uint32_t needVerifyPreHashCount, 
	uint64_t gasFee,
	std::string &txhash)
{

	if (addr.size() == 0 )
	{
		ERRORLOG("DoDeployContract addr is empty");
		return;
	}

	if (contract.size() == 0 )
	{
		ERRORLOG("DoDeployContract contract is empty");
		return;
	}

	if (abi.size() == 0 )
	{
		ERRORLOG("DoDeployContract abi is empty");
		return;
	}

	CTransaction outTx;
    int ret = TxHelper::CreateDeployContractMessage(addr, contract_name, contract, abi, needVerifyPreHashCount, gasFee, outTx);
	if(ret != 0)
	{
		ERRORLOG("DoDeployContract: TxHelper::CreateDeployContractMessage error!!");
		return;
	}

	util::JsonPrintOptions options;
	options.add_whitespace = true;
	options.always_print_primitive_fields = true;
	options.preserve_proto_field_names = true;

	std::string out_str;
	util::MessageToJsonString(outTx, &out_str, options);
	std::cout << "CTransaction:" << std::endl;	
	std::cout << out_str << std::endl;	

	std::vector<std::string> addrs;
	for (int i = 0; i < outTx.vin_size(); i++)
	{
		CTxin * txin = outTx.mutable_vin(i);;
		std::string pub = txin->mutable_scriptsig()->pub();
		txin->clear_scriptsig();
		addrs.push_back(GetBase58Addr(pub));
	}

	std::string serTx = outTx.SerializeAsString();

	size_t encodeLen = serTx.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)serTx.data(), serTx.size(), encode);
	std::string encodeStr( (char *)encode, codeLen );

	std::string encodeStrHash = getsha256hash(encodeStr);

	//签名
	for (int i = 0; i < outTx.vin_size(); i++)
	{
		std::string addr = addrs[i];
		std::string signature;
		std::string strPub;
		g_AccountInfo.Sign(addr.c_str(), encodeStrHash, signature);
		g_AccountInfo.GetPubKeyStr(addr.c_str(), strPub);
		CTxin * txin = outTx.mutable_vin(i);
		txin->mutable_scriptsig()->set_sign(signature);
		txin->mutable_scriptsig()->set_pub(strPub);
	}
	
	serTx = outTx.SerializeAsString();

	TxMsg txMsg;
	txMsg.set_version(getVersion());
	txMsg.set_tx( serTx );
	txMsg.set_txencodehash( encodeStrHash );

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	unsigned int top = 0;
	pRocksDb->GetBlockTop(txn, top);	
	txMsg.set_top(top);

	std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        ERRORLOG("GetBestChainHash return no zero");
        return;
    }
    txMsg.set_prevblkhash(blockHash);	
    txMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));

	auto msg = make_shared<TxMsg>(txMsg);

	ret = DoHandleTx(msg, txhash);
	DEBUGLOG("交易处理结果，ret:{}  txHash：{}", ret, txhash);
	
}




int TxHelper::DeployContractToDB(const CTransaction & tx, 
	std::shared_ptr<Rocksdb> pRocksDb, 
	Transaction* txn)
{


    auto extra = nlohmann::json::parse(tx.extra());
    std::string type = extra["TransactionType"].get<std::string>();
	if(type != TXTYPE_CONTRACT_DEPLOY)
	{
		return -1;
	}
	if(CheckTransactionType(tx) != kTransactionType_Tx)
	{
		return -2;
	}


    std::string contract_name = extra["ContractName"].get<std::string>();
    std::string contract = extra["Contract"].get<std::string>();
	contract =  base64Decode(contract);
    std::string abi = extra["Abi"].get<std::string>();
	abi = base64Decode(abi);

	pRocksDb->SetContractByAddress(txn, contract_name, contract, abi);
	return 0;	

}	



int TxHelper::CreateExecuteContractMessage(const std::string & addr, 
	const std::string &contract, 
	const std::string &action,
	const std::string &params,
	uint32_t needVerifyPreHashCount, 
	uint64_t minerFees, 
	CTransaction & outTx)
{
	if (addr.size() == 0 )
	{
		ERRORLOG("CreateExecuteContractMessage addr is empty");
		return -1;
	}

	if (contract.size() == 0 )
	{
		ERRORLOG("CreateExecuteContractMessage contract is empty");
		return -1;
	}

	if (action.size() == 0 )
	{
		ERRORLOG("CreateExecuteContractMessage abi is empty");
		return -1;
	}

	if (params.size() == 0 )
	{
		ERRORLOG("CreateExecuteContractMessage params is empty");
		return -1;
	}

	std::vector<std::string> fromAddr;
	fromAddr.push_back(addr); 

    int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(CreateExecuteContractMessage) TransactionInit failed !");
		return -4;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};
	
	// 支付的燃料费
	uint64_t amount =  (needVerifyPreHashCount - 1) * minerFees;

	// 是否需要打包费
	bool bIsNeedPackage = IsNeedPackage(fromAddr);
	
	// 交易发起方支付打包费
	uint64_t publicNodePackageFee = 0;
	if (bIsNeedPackage)
	{
		if ( 0 != pRocksDb->GetDevicePackageFee(publicNodePackageFee) )
		{
			ERRORLOG("CreateExecuteContractMessage GetDevicePackageFee failed");
			return -5;
		}

		amount += publicNodePackageFee;
	}

	std::map<std::string, std::vector<std::string>> utxoHashs;
	for(auto& addr:fromAddr)
	{
		std::vector<std::string> tmp;
		db_status = pRocksDb->GetUtxoHashsByAddress(txn, addr, tmp);
		if (db_status != 0) {
			ERRORLOG("CreateExecuteContractMessage GetUtxoHashsByAddress");
			return -6;
		}
		utxoHashs[addr] = tmp;
	}

	uint64_t total = 0;
	std::string change_addr;
	std::set<std::string> txowners;
	for(auto& addr:fromAddr)
	{
		for (auto& item : utxoHashs[addr])
		{
			std::string strTxRaw;
			if (pRocksDb->GetTransactionByHash(txn, item, strTxRaw) != 0)
			{
				continue;
			}
			CTransaction utxoTx;
			utxoTx.ParseFromString(strTxRaw);

			for (int i = 0; i < utxoTx.vout_size(); i++)
			{
				CTxout txout = utxoTx.vout(i);
				if(txout.scriptpubkey() == addr)
				{
					txowners.insert(addr);
					change_addr = addr;
					total += txout.value();

					CTxin * txin = outTx.add_vin();
					CTxprevout * prevout = txin->mutable_prevout();
					prevout->set_hash(utxoTx.hash());
					prevout->set_n(utxoTx.n());

					std::string strPub;
					g_AccountInfo.GetPubKeyStr(txout.scriptpubkey().c_str(), strPub);
					txin->mutable_scriptsig()->set_pub(strPub);
				}
			}
			if (total >= amount)
			{
				break;
			}
		}
		if (total >= amount)
		{
			break;
		}		
	}
	if (total < amount)
	{
		ERRORLOG("CreateExecuteContractMessage total < amount");
		return -7;
	}

	if((uint64_t)minerFees < g_minSignFee || (uint64_t)minerFees > g_maxSignFee)
	{
		return -15;
	}
	
	// 设置找零地址
	CTxout * txoutFromAddr = outTx.add_vout();
	txoutFromAddr->set_value(total - amount);
	txoutFromAddr->set_scriptpubkey(change_addr);

	uint64_t time = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
	outTx.set_time(time);

	std::string tmpAddr;
	for (auto & addr : txowners)
	{
		tmpAddr += addr;
		tmpAddr += "_";
	}
	
	tmpAddr.erase(tmpAddr.end() -1);
	
	outTx.set_txowner(tmpAddr);

	outTx.set_ip(net_get_self_node_id());

	nlohmann::json extra;
	extra["NeedVerifyPreHashCount"] = needVerifyPreHashCount;
	extra["SignFee"] = minerFees;
	extra["TransactionType"] = TXTYPE_CONTRACT_EXECUTE;
	extra["PackageFee"] = publicNodePackageFee;

	extra["Contract"] = contract;
	extra["Action"] = action;
	extra["Param"] = base64Encode(params);

	outTx.set_extra(extra.dump());

	return 0;		
}		



void TxHelper::DoeExecuteContract(const std::string & addr, 
	const std::string &contract, 
	const std::string &action,
	const std::string &params,
	uint32_t needVerifyPreHashCount, 
	uint64_t gasFee,
	std::string &txhash)
{
	if (addr.size() == 0 )
	{
		ERRORLOG("DoeExecuteContract addr is empty");
		return;
	}

	if (contract.size() == 0 )
	{
		ERRORLOG("DoeExecuteContract contract is empty");
		return;
	}

	if (action.size() == 0 )
	{
		ERRORLOG("DoeExecuteContract action is empty");
		return;
	}

	if (params.size() == 0 )
	{
		ERRORLOG("DoeExecuteContract params is empty");
		return;
	}

	CTransaction outTx;
    int ret = TxHelper::CreateExecuteContractMessage(addr, contract, action, params, needVerifyPreHashCount, gasFee, outTx);
	if(ret != 0)
	{
		ERRORLOG("DoeExecuteContract: TxHelper::CreateDeployContractMessage error!!");
		return;
	}

	util::JsonPrintOptions options;
	options.add_whitespace = true;
	options.always_print_primitive_fields = true;
	options.preserve_proto_field_names = true;

	std::string out_str;
	util::MessageToJsonString(outTx, &out_str, options);
	std::cout << "CTransaction:" << std::endl;	
	std::cout << out_str << std::endl;	

	std::vector<std::string> addrs;
	for (int i = 0; i < outTx.vin_size(); i++)
	{
		CTxin * txin = outTx.mutable_vin(i);;
		std::string pub = txin->mutable_scriptsig()->pub();
		txin->clear_scriptsig();
		addrs.push_back(GetBase58Addr(pub));
	}

	std::string serTx = outTx.SerializeAsString();

	size_t encodeLen = serTx.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)serTx.data(), serTx.size(), encode);
	std::string encodeStr( (char *)encode, codeLen );

	std::string encodeStrHash = getsha256hash(encodeStr);

	//签名
	for (int i = 0; i < outTx.vin_size(); i++)
	{
		std::string addr = addrs[i];
		std::string signature;
		std::string strPub;
		g_AccountInfo.Sign(addr.c_str(), encodeStrHash, signature);
		g_AccountInfo.GetPubKeyStr(addr.c_str(), strPub);
		CTxin * txin = outTx.mutable_vin(i);
		txin->mutable_scriptsig()->set_sign(signature);
		txin->mutable_scriptsig()->set_pub(strPub);
	}
	
	serTx = outTx.SerializeAsString();

	TxMsg txMsg;
	txMsg.set_version(getVersion());
	txMsg.set_tx( serTx );
	txMsg.set_txencodehash( encodeStrHash );

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	unsigned int top = 0;
	pRocksDb->GetBlockTop(txn, top);	
	txMsg.set_top(top);

	std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        ERRORLOG("GetBestChainHash return no zero");
        return;
    }
    txMsg.set_prevblkhash(blockHash);	
    txMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));

	auto msg = make_shared<TxMsg>(txMsg);

	ret = DoHandleTx(msg, txhash);
	DEBUGLOG("交易处理结果，ret:{}  txHash：{}", ret, txhash);
}		



int TxHelper::ExecuteContractToDB(const CTransaction & tx, 
	std::shared_ptr<Rocksdb> pRocksDb, 
	Transaction* txn)
{


    auto extra = nlohmann::json::parse(tx.extra());
    std::string type = extra["TransactionType"].get<std::string>();
	if(type != TXTYPE_CONTRACT_EXECUTE)
	{
		return -1;
	}
	if(CheckTransactionType(tx) != kTransactionType_Tx)
	{
		return -2;
	}

    std::string contract = extra["Contract"].get<std::string>();
    std::string action = extra["Action"].get<std::string>();
    std::string param = extra["Param"].get<std::string>();
	param =  base64Decode(param);

	// 从链上获取contract， abi
	std::string contract_raw;
	std::string abi_raw;

	pRocksDb->GetContractByAddress(txn, contract,  contract_raw, abi_raw);
    wasm::wasm_context cnt(wasm::ExecuteType::block, contract, "", contract_raw, abi_raw, action, param, 0, tx.txowner());
    cnt.execute();

	return 0;	

}	

