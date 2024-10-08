#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string>
#include <set>
#include <algorithm>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <shared_mutex>
#include <mutex>
#include "ca_transaction.h"
#include "ca_message.h"
#include "ca_hexcode.h"
#include "ca_buffer.h"
#include "ca_serialize.h"
#include "ca_util.h"
#include "ca_global.h"
#include "ca_coredefs.h"
#include "ca_hexcode.h"
#include "Crypto_ECDSA.h"
#include "ca_interface.h"
#include "../include/logging.h"
#include "ca.h"
#include "ca_test.h"
#include "../include/net_interface.h"
#include "ca_clientinfo.h"
#include "../include/ScopeGuard.h"
#include "ca_clientinfo.h"
#include "../common/config.h"
#include "ca_clientinfo.h"
#include "ca_console.h"
#include "ca_device.h"
#include <string.h>
#include "ca_header.h"
#include "ca_sha2.h"
#include "ca_base64.h"
#include "ca_txhelper.h"
#include "ca_pwdattackchecker.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "../utils/time_util.h"
#include "../common/devicepwd.h"
#include "../net/node_cache.h"

static std::mutex s_ResMutex;
#include "./ca_blockpool.h"
#include "../utils/string_util.h"
#include "getmac.pb.h"
#include "ca_AwardAlgorithm.h"

#include "proto/ca_protomsg.pb.h"
#include "ca_txhelper.h"
#include "ca_txvincache.h"
#include "ca_txconfirmtimer.h"
#include "ca_block_http_callback.h"
#include "interface.pb.h"

std::shared_mutex MinutesCountLock;
static const int REASONABLE_HEIGHT_RANGE = 10;

template<typename Ack> void ReturnAckCode(const MsgData& msgdata, std::map<int32_t, std::string> errInfo, Ack & ack, int32_t code, const std::string & extraInfo = "");
template<typename TxReq> int CheckAddrs( const std::shared_ptr<TxReq>& req);

int GetAddrsFromMsg( const std::shared_ptr<CreateMultiTxMsgReq>& msg, 
                     std::vector<std::string> &fromAddr,
                     std::map<std::string, int64_t> &toAddr);

int StringSplit(std::vector<std::string>& dst, const std::string& src, const std::string& separator)
{
    if (src.empty() || separator.empty())
        return 0;

    int nCount = 0;
    std::string temp;
    size_t pos = 0, offset = 0;

    // 分割第1~n-1个
    while((pos = src.find_first_of(separator, offset)) != std::string::npos)
    {
        temp = src.substr(offset, pos - offset);
        if (temp.length() > 0)
		{
            dst.push_back(temp);
            nCount ++;
        }
        offset = pos + 1;
    }

    // 分割第n个
    temp = src.substr(offset, src.length() - offset);
    if (temp.length() > 0)
	{
        dst.push_back(temp);
        nCount ++;
    }

    return nCount;
}

uint64_t CheckBalanceFromRocksDb(const std::string & address)
{
	if (address.size() == 0)
	{
		return 0;
	}

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(CheckBalanceFromRocksDb) TransactionInit failed !");
		return 0;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	int64_t balance = 0;
	int r = pRocksDb->GetBalanceByAddress(txn, address, balance);
	if (r != 0)
	{
		return 0;
	}

	return balance;
}

bool FindUtxosFromRocksDb(const std::string & fromAddr, const std::string & toAddr, uint64_t amount, uint32_t needVerifyPreHashCount, uint64_t minerFees, CTransaction & outTx, std::string utxoStr)
{
	if (fromAddr.size() == 0 || toAddr.size() == 0)
	{
		ERRORLOG("FindUtxosFromRocksDb fromAddr toAddr ==0");
		return false;
	}

	//{{ Check pending transaction in Cache, 20201215
	std::vector<string> vectFromAddr{ fromAddr };
	if (MagicSingleton<TxVinCache>::GetInstance()->IsConflict(vectFromAddr))
	{
		ERRORLOG("Pending transaction is in Cache fromAddr{}!", fromAddr);
		return false;
	}
	//}}
	
	uint64_t totalGasFee = (needVerifyPreHashCount - 1) * minerFees;
	uint64_t amt = fromAddr == toAddr ? totalGasFee : amount + totalGasFee;
	
    int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(FindUtxosFromRocksDb) TransactionInit failed !");
		return false;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	uint64_t total = 0;
	std::vector<std::string> utxoHashs;
	std::vector<std::string> pledgeUtxoHashs;

	// 解质押交易
	if (fromAddr == toAddr)
	{
		db_status = pRocksDb->GetPledgeAddressUtxo(txn, fromAddr, pledgeUtxoHashs);
		if (db_status != 0)
		{
			return false;
		}

		std::string strTxRaw;
		if (pRocksDb->GetTransactionByHash(txn, utxoStr, strTxRaw) != 0)
		{
			return false;
		}

		CTransaction utxoTx;
		utxoTx.ParseFromString(strTxRaw);

		for (int i = 0; i < utxoTx.vout_size(); i++)
		{
			CTxout txout = utxoTx.vout(i);
			if (txout.scriptpubkey() != VIRTUAL_ACCOUNT_PLEDGE)
			{
				continue;
			}
			amount = txout.value();
		}
	}
	
	db_status = pRocksDb->GetUtxoHashsByAddress(txn, fromAddr, utxoHashs);
	if (db_status != 0) 
	{
		ERRORLOG("FindUtxosFromRocksDb GetUtxoHashsByAddress");
		return false;
	}
	
	// 去重
	std::set<std::string> setTmp(utxoHashs.begin(), utxoHashs.end());
	utxoHashs.clear();
	utxoHashs.assign(setTmp.begin(), setTmp.end());

	std::reverse(utxoHashs.begin(), utxoHashs.end());
	if (pledgeUtxoHashs.size() > 0)
	{
		std::reverse(pledgeUtxoHashs.begin(), pledgeUtxoHashs.end());
	}

	// 记录手续费使用的utxo
	std::vector<std::string> vinUtxoHash;

	for (auto &item : utxoHashs)
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
			if (txout.scriptpubkey() != fromAddr)
			{
				continue;
			}
			else
			{
				total += txout.value();

				CTxin * txin = outTx.add_vin();
				CTxprevout * prevout = txin->mutable_prevout();
				prevout->set_hash(utxoTx.hash());
				prevout->set_n(utxoTx.n());
				// TODO

				vinUtxoHash.push_back(utxoTx.hash());
			}

			// 解质押会产生一个UTXO 两个vout同时给质押账号的情况，需要都算进去
			if (i < utxoTx.vout_size() - 1)
			{
				continue;
			}

			if (total >= amt)
			{
				break;
			}
		}

		if (total >= amt)
		{
			break;
		}
	}


	if (total < amt)
	{
		ERRORLOG("FindUtxosFromRocksDb total < amt");
		return false;
	}

	if (fromAddr == toAddr)
	{
		std::string utxoTxStr;
		if (pRocksDb->GetTransactionByHash(txn, utxoStr, utxoTxStr) != 0)
		{
			ERRORLOG("GetTransactionByHash error!");
			return false;
		}

		CTransaction utxoTx;
		utxoTx.ParseFromString(utxoTxStr);
		for (int i = 0; i < utxoTx.vout_size(); i++)
		{
			CTxout txout = utxoTx.vout(i);
			if (txout.scriptpubkey() != VIRTUAL_ACCOUNT_PLEDGE)
			{
				bool isAlreadyAdd = false;
				for (auto &hash : vinUtxoHash)
				{
					// 手续费中使用了该utxo
					if (hash == utxoTx.hash())
					{
						isAlreadyAdd = true;
					}
				}

				// 该utxo中有一个vout是可正常使用的资产，需要计算重新给到账户
				if (txout.scriptpubkey() == fromAddr && !isAlreadyAdd)
				{
					for (auto &utxo : utxoHashs)
					{
						// 该utxo的可用资产还未使用时需要计算
						if (utxo == utxoTx.hash())
						{
							total += txout.value();
						}
					}
				}
				continue;
			}

			CTxin * txin = outTx.add_vin();
			CTxprevout * prevout = txin->mutable_prevout();
			prevout->set_hash(utxoTx.hash());
			prevout->set_n(utxoTx.n());
		}
	}

	CTxout * txoutToAddr = outTx.add_vout();
	txoutToAddr->set_value(amount);
	txoutToAddr->set_scriptpubkey(toAddr);

	CTxout * txoutFromAddr = outTx.add_vout();
	txoutFromAddr->set_value(total - amt);
	txoutFromAddr->set_scriptpubkey(fromAddr);

	uint64_t time = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
	outTx.set_time(time);
	outTx.set_txowner(fromAddr);
	outTx.set_ip(net_get_self_node_id());
	
	return true;
}

TransactionType CheckTransactionType(const CTransaction & tx)
{
	if( tx.time() == 0 || tx.hash().length() == 0 || tx.vin_size() == 0 || tx.vout_size() == 0)
	{
		return kTransactionType_Unknown;
	}
	

	CTxin txin = tx.vin(0);
	if ( txin.scriptsig().sign() == std::string(FEE_SIGN_STR))
	{
		return kTransactionType_Fee;
	}
	else if (txin.scriptsig().sign() == std::string(EXTRA_AWARD_SIGN_STR))
	{
		return kTransactionType_Award;
	}

	return kTransactionType_Tx;
}

bool checkTop(int top)
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if(txn == NULL )
	{
		ERRORLOG("(checkTop) TransactionInit failed ! ");
		return false;
	}
	bool bRollback = true;
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, bRollback);
	};

	unsigned int mytop = 0;
	pRocksDb->GetBlockTop(txn, mytop);	

	if(top < (int)mytop - 4 )
	{
		ERRORLOG("checkTop fail other top:{} my top:{}", top, (int)mytop);
		return false;
	}
	else if(top > (int)mytop + 1)
	{
		ERRORLOG("checkTop fail other top:{} my top:{}", top, (int)mytop);
		return false;
	}
	else
	{
		return true;
	}
}

bool checkTransaction(const CTransaction & tx)
{
	if (tx.vin_size() == 0 || tx.vout_size() == 0)
	{
		return false;
	}

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if ( txn == NULL )
	{
		ERRORLOG("(FindUtxosFromRocksDb) TransactionInit failed !");
		return false;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, false);
	};

	int db_status = 0;

	uint64_t total = 0;
	for (int i = 0; i < tx.vout_size(); i++)
	{
		CTxout txout = tx.vout(i);
		total += txout.value();
	}

	// 检查总金额
	if (total < 0 || total > 21000000LL * COIN)
	{
		return false;
	}

	std::vector<CTxin> vTxins;
	for (int i = 0; i < tx.vin_size(); i++)
	{
		vTxins.push_back(tx.vin(i));
	}

	bool isRedeem = false;
	nlohmann::json extra = nlohmann::json::parse(tx.extra());
	std::string txType = extra["TransactionType"].get<std::string>();
	std::string redeemUtxo;

	if (txType == TXTYPE_REDEEM)
	{
		isRedeem= true;

		if (CheckTransactionType(tx) == kTransactionType_Tx)
		{
			nlohmann::json txInfo = extra["TransactionInfo"].get<nlohmann::json>();
			redeemUtxo = txInfo["RedeemptionUTXO"];

			// 检查质押时间
			if ( 0 != IsMoreThan30DaysForRedeem(redeemUtxo) )
			{
				ERRORLOG("Redeem time is less than 30 days!");
				return false;
			}
		}
	}

	if (CheckTransactionType(tx) == kTransactionType_Tx)
	{
		// 检查txowner和vin签名者是否一致
		std::vector<std::string> vinSigners;
		for (const auto & vin : vTxins)
		{
			std::string pubKey = vin.scriptsig().pub();
			std::string addr = GetBase58Addr(pubKey);
			if (vinSigners.end() == find(vinSigners.begin(), vinSigners.end(), addr))
			{
				vinSigners.push_back(addr);
			}
		}

		std::vector<std::string> txOwners = TxHelper::GetTxOwner(tx);
		if (vinSigners != txOwners)
		{
			ERRORLOG("TxOwner or vin signer error!");
			return false;
		}

		// utxo是否存在
		for (const auto & vin : vTxins)
		{
			std::string pubKey = vin.scriptsig().pub();
			std::string addr = GetBase58Addr(pubKey);

			std::vector<std::string> utxos;
			if (pRocksDb->GetUtxoHashsByAddress(txn, addr, utxos))
			{
				ERRORLOG("GetUtxoHashsByAddress error !");
				return false;
			}
			
			std::vector<std::string> pledgeUtxo;
			pRocksDb->GetPledgeAddressUtxo(txn, addr, pledgeUtxo);
			if (utxos.end() == find(utxos.begin(), utxos.end(), vin.prevout().hash()))
			{
				if (isRedeem)
				{
					if (vin.prevout().hash() != redeemUtxo)
					{
						ERRORLOG("tx vin not found !");
						return false;
					}
				}
				else
				{
					ERRORLOG("tx vin not found !");
					return false;
				}
			}
		}
	}

	// 检查是否有重复vin
	std::sort(vTxins.begin(), vTxins.end(), [](const CTxin & txin0, const CTxin & txin1){
		if (txin0.prevout().n() > txin1.prevout().n())
		{
			return true;
		}
		else
		{
			return false;
		}
	});
	auto iter = std::unique(vTxins.begin(), vTxins.end(), [](const CTxin & txin0, const CTxin & txin1){
		return txin0.prevout().n() == txin1.prevout().n() &&
				txin0.prevout().hash() == txin1.prevout().hash() &&
				txin0.scriptsig().sign() == txin1.scriptsig().sign();
	});

	if (iter != vTxins.end())
	{
		if (isRedeem)
		{
			std::vector<std::string> utxos;
			string txowner = TxHelper::GetTxOwner(tx)[0];
			db_status = pRocksDb->GetPledgeAddressUtxo(txn, TxHelper::GetTxOwner(tx)[0], utxos);
			if (db_status != 0)
			{
				return false;
			}
			auto utxoIter = find(utxos.begin(), utxos.end(), iter->prevout().hash());
			if (utxoIter == utxos.end())
			{
				std::string txRaw;
				db_status = pRocksDb->GetTransactionByHash(txn, iter->prevout().hash(), txRaw);
				if (db_status != 0)
				{
					return false;
				}

				CTransaction utxoTx;
				utxoTx.ParseFromString(txRaw);
				if (utxoTx.vout_size() == 2)
				{
					if (utxoTx.vout(0).scriptpubkey() != utxoTx.vout(1).scriptpubkey())
					{
						return false;
					}
				}
			}
		}
		else
		{
			std::string txRaw;
			db_status = pRocksDb->GetTransactionByHash(txn, iter->prevout().hash(), txRaw);
			if (db_status != 0)
			{
				return false;
			}

			CTransaction utxoTx;
			utxoTx.ParseFromString(txRaw);
			if (utxoTx.vout_size() == 2)
			{
				if (utxoTx.vout(0).scriptpubkey() != utxoTx.vout(1).scriptpubkey())
				{
					return false;
				}
			}
		}
	}

	if (CheckTransactionType(tx) == kTransactionType_Tx)
	{
		// 交易
		for (auto &txin : vTxins)
		{

			if (txin.prevout().n() == 0xFFFFFFFF)
			{
				return false;
			}
		}
	}
	else
	{
		// 奖励
		unsigned int height = 0;
		db_status = pRocksDb->GetBlockTop(txn, height);
        if (db_status != 0) 
		{
            return false;
        }
		if (tx.signprehash().size() > 0 && 0 == height)
		{
			return false;
		}

		CTxin txin0 = tx.vin(0);
		int scriptSigLen = txin0.scriptsig().sign().length() + txin0.scriptsig().pub().length();
		if (scriptSigLen < 2 || scriptSigLen > 100)
		{
			return false;
		}

		for (auto &txin : vTxins)
		{
			if (height == 0 && (txin.scriptsig().sign() + txin.scriptsig().pub()) == OTHER_COIN_BASE_TX_SIGN)
			{
				return false;
			}
		}
	}
	
	return true;
}

std::vector<std::string> randomNode(unsigned int n)
{
	std::vector<Node> nodeInfos ;
	if (Singleton<PeerNode>::get_instance()->get_self_node().is_public_node)
	{
		nodeInfos = Singleton<PeerNode>::get_instance()->get_nodelist();
		DEBUGLOG("randomNode PeerNode size() = {}", nodeInfos.size());
	}
	else
	{
		nodeInfos = Singleton<NodeCache>::get_instance()->get_nodelist();
		DEBUGLOG("randomNode NodeCache size() = {}", nodeInfos.size());
	}
	std::vector<std::string> v;
	for (const auto & i : nodeInfos)
	{
		v.push_back(i.id);
	}
	
	unsigned int nodeSize = n;
	std::vector<std::string> sendid;
	if ((unsigned int)v.size() < nodeSize)
	{
		DEBUGLOG("not enough node to send");
		return  sendid;
	}

	std::string s = net_get_self_node_id();
	auto iter = std::find(v.begin(), v.end(), s);
	if (iter != v.end())
	{
		v.erase(iter);
	}

	if (v.empty())
	{
		return v;
	}

	if (v.size() <= nodeSize)
	{
		for (auto & i : v)
		{
			sendid.push_back(i);	
		}
	}
	else
	{
		std::set<int> rSet;
		srand(time(NULL));
		while (1)
		{
			int i = rand() % v.size();
			rSet.insert(i);
			if (rSet.size() == nodeSize)
			{
				break;
			}
		}

		for (auto &i : rSet)
		{
			sendid.push_back(v[i]);
		}
	}
	
	return sendid;
}

int GetSignString(const std::string & message, std::string & signature, std::string & strPub)
{
	if (message.size() <= 0)
	{
		ERRORLOG("(GetSignString) parameter is empty!");
		return -1;
	}

	bool result = false;
	result = SignMessage(g_privateKey, message, signature);
	if (!result)
	{
		return -1;
	}

	GetPublicKey(g_publicKey, strPub);
	return 0;
}

/** 手机端端创建交易体 */
int CreateTransactionFromRocksDb( const std::shared_ptr<CreateTxMsgReq>& msg, std::string &serTx)
{
	if ( msg == NULL )
	{
		return -1;
	}

	CTransaction outTx;
	double amount = stod( msg->amt() );
	uint64_t amountConvert = amount * DECIMAL_NUM;
	double minerFeeConvert = stod( msg->minerfees() );
	if(minerFeeConvert <= 0)
	{
		ERRORLOG("phone -> minerFeeConvert == 0 !");
		return -2;
	}
	uint64_t gasFee = minerFeeConvert * DECIMAL_NUM;

	uint32_t needVerifyPreHashCount = stoi( msg->needverifyprehashcount() );

    std::vector<std::string> fromAddr;
    fromAddr.emplace_back(msg->from());

    std::map<std::string, int64_t> toAddr;
    toAddr[msg->to()] = amountConvert;

	int ret = TxHelper::CreateTxMessage(fromAddr,toAddr, needVerifyPreHashCount, gasFee, outTx);
	if( ret != 0)
	{
		ERRORLOG("CreateTransaction Error ...\n");
		return -3;
	}
	
	for (int i = 0; i < outTx.vin_size(); i++)
	{
		CTxin * txin = outTx.mutable_vin(i);;
		txin->clear_scriptsig();
	}
	
	serTx = outTx.SerializeAsString();
	return 0;
}


int GetRedemUtxoAmount(const std::string & redeemUtxoStr, uint64_t & amount)
{
	if (redeemUtxoStr.size() != 64)
	{
		ERRORLOG("(GetRedemUtxoAmount) param error !");
		return -1;
	}

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(VerifyBlockHeader) TransactionInit failed !");
		return -2;
	}

	bool bRollback = true;
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, bRollback);
	};

	std::string txRaw;
	if ( 0 != pRocksDb->GetTransactionByHash(txn, redeemUtxoStr, txRaw) )
	{
		ERRORLOG("(GetRedemUtxoAmount) GetTransactionByHash failed !");
		return -3;
	}

	CTransaction tx;
	tx.ParseFromString(txRaw);

	for (int i = 0; i < tx.vout_size(); ++i)
	{
		CTxout txout = tx.vout(i);
		if (txout.scriptpubkey() == VIRTUAL_ACCOUNT_PLEDGE)
		{
			amount = txout.value();
		}
	}

	return 0;
}


bool VerifyBlockHeader(const CBlock & cblock)
{
	// uint64_t t1 = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
	std::string hash = cblock.hash();
    int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(VerifyBlockHeader) TransactionInit failed !");
		return false;
	}

	bool bRollback = true;
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, bRollback);
	};

	std::string strTempHeader;
	db_status = pRocksDb->GetBlockByBlockHash(txn, hash, strTempHeader);

	if (strTempHeader.size() != 0)
	{
		DEBUGLOG("BlockInfo has exist , do not need to add ...");
		bRollback = true;
        return false;
	}

	std::string strPrevHeader;
	db_status = pRocksDb->GetBlockByBlockHash(txn, cblock.prevhash(), strPrevHeader);
    if (db_status != 0) 
	{
        ERRORLOG("VerifyBlockHeader (GetBlockByBlockHash) failed db_status:{}! ", db_status );
    }
	if (strPrevHeader.size() == 0)
	{
		ERRORLOG("bp_block_valid lookup hashPrevBlock ERROR !!!");
		bRollback = true;
		return false;
	}

	// 区块检查

	// 时间戳检查	
	std::string strGenesisBlockHash;
	db_status = pRocksDb->GetBlockHashByBlockHeight(txn, 0, strGenesisBlockHash);
	if (db_status != 0)
	{
		ERRORLOG("GetBlockHashByBlockHeight failed!" );
		return false;
	}
	std::string strGenesisBlockHeader;
	pRocksDb->GetBlockByBlockHash(txn, strGenesisBlockHash, strGenesisBlockHeader);
	if (db_status != 0)
	{
		ERRORLOG("GetBlockHashByBlockHeight failed!" );
		return false;
	}

	if (strGenesisBlockHeader.length() == 0)
	{
		ERRORLOG("Genesis Block is not exist");
		return false;
	}
	
	CBlock genesisBlockHeader;
	genesisBlockHeader.ParseFromString(strGenesisBlockHeader);
	uint64_t blockHeaderTimestamp = cblock.time();
	uint64_t genesisBlockHeaderTimestamp = genesisBlockHeader.time();
	if (blockHeaderTimestamp == 0 || genesisBlockHeaderTimestamp == 0 || blockHeaderTimestamp <= genesisBlockHeaderTimestamp)
	{
		ERRORLOG("block timestamp error!");
		return false;
	}

	if (cblock.txs_size() == 0)
	{
		ERRORLOG("cblock.txs_size() == 0");
		bRollback = true;
		return false;
	}

	if (cblock.SerializeAsString().size() > MAX_BLOCK_SIZE)
	{
		ERRORLOG("cblock.SerializeAsString().size() > MAX_BLOCK_SIZE");
		bRollback = true;
		return false;
	}

	if (CalcBlockHeaderMerkle(cblock) != cblock.merkleroot())
	{
		ERRORLOG("CalcBlockHeaderMerkle(cblock) != cblock.merkleroot()");
		bRollback = true;
		return false;
	}

	// 获取本块的签名个数
	uint64_t blockSignNum = 0;
	for (auto & txTmp : cblock.txs())
	{
		if (CheckTransactionType(txTmp) == kTransactionType_Fee)
		{
			blockSignNum = txTmp.vout_size();
		}
	}

	std::map<std::string, uint64_t> addrAwards;
	// 获取奖励交易中的节点信息,计算各个账号奖励值,用于校验
	if (cblock.height() > g_compatMinHeight)
	{
		for (auto & txTmp : cblock.txs())
		{
			if (CheckTransactionType(txTmp) == kTransactionType_Award)
			{
				nlohmann::json txExtra;
				try
				{
					txExtra = nlohmann::json::parse(txTmp.extra());
				}
				catch(const std::exception& e)
				{
					std::cerr << e.what() << '\n';
					ERRORLOG("json::parse error");
					bRollback = true;
					return false;
				}
				
				std::vector<std::string> addrs;
				std::vector<double> onlines;
				std::vector<uint64_t> awardTotals;
				std::vector<uint64_t> signSums;

				for(const auto& info : txExtra["OnlineTime"])
				{
					try
					{
						addrs.push_back(info["Addr"].get<std::string>());
						onlines.push_back(info["OnlineTime"].get<double>());
						awardTotals.push_back(info["AwardTotal"].get<uint64_t>());
						signSums.push_back(info["SignSum"].get<uint64_t>());
					}
					catch(const std::exception& e)
					{
						std::cerr << e.what() << '\n';
						bRollback = true;
						ERRORLOG("json::parse error");
						return false;
					}
				}

				if (addrs.size() == 0 || onlines.size() == 0 || awardTotals.size() == 0 || signSums.size() == 0)
				{
					if (cblock.height() != 0)
					{
						ERRORLOG("Get sign node info error !");
						bRollback = true;
						return false;
					}
				}
				else
				{
					a_award::AwardAlgorithm awardAlgorithm;
					if ( 0 != awardAlgorithm.Build(blockSignNum, addrs, onlines, awardTotals, signSums) )
					{
						ERRORLOG("awardAlgorithm.Build() failed!");
						bRollback = true;
						return false;
					}

					auto awardInfo = awardAlgorithm.GetDisAward();
					for (auto & award : awardInfo)
					{
						addrAwards.insert(std::make_pair(award.second, award.first));
					}	
				}
				// awardAlgorithm.TestPrint(true);
			}
		}
	}

	// 交易检查
	for (int i = 0; i < cblock.txs_size(); i++)
	{
		CTransaction tx = cblock.txs(i);
		if (!checkTransaction(tx))
		{
			ERRORLOG("checkTransaction(tx)");
			bRollback = true;
			return false;
		}

		bool iscb = CheckTransactionType(tx) == kTransactionType_Fee || CheckTransactionType(tx) == kTransactionType_Award;

		if (iscb && 0 == tx.signprehash_size())
		{
			continue;
		}

		std::string bestChainHash;
		db_status = pRocksDb->GetBestChainHash(txn, bestChainHash);
        if (db_status != 0) {
			ERRORLOG(" pRocksDb->GetBestChainHash db_status{}", db_status);
			bRollback = true;
            return false;
        }
		bool isBestChainHash = bestChainHash.size() != 0;
		if (! isBestChainHash && iscb && 0 == cblock.txs_size())
		{
			continue;
		}

		if (0 == cblock.txs_size() && ! isBestChainHash)
		{
			ERRORLOG("0 == cblock.txs_size() && ! isBestChainHash");
			bRollback = true;
			return false;
		}

		if (isBestChainHash)
		{
			int verifyPreHashCount = 0;
			std::string txBlockHash;

            std::string txHashStr;
            
            for (int i = 0; i < cblock.txs_size(); i++)
            {
                CTransaction transaction = cblock.txs(i);
                if ( CheckTransactionType(transaction) == kTransactionType_Tx)
                {
                    CTransaction copyTx = transaction;
                    for (int i = 0; i != copyTx.vin_size(); ++i)
                    {
                        CTxin * txin = copyTx.mutable_vin(i);
                        txin->clear_scriptsig();
                    }

                    copyTx.clear_signprehash();
                    copyTx.clear_hash();

                    std::string serCopyTx = copyTx.SerializeAsString();

                    size_t encodeLen = serCopyTx.size() * 2 + 1;
                    unsigned char encode[encodeLen] = {0};
                    memset(encode, 0, encodeLen);
                    long codeLen = base64_encode((unsigned char *)serCopyTx.data(), serCopyTx.size(), encode);
                    std::string encodeStr( (char *)encode, codeLen );

                    txHashStr = getsha256hash(encodeStr);
                }
            }

			if (! VerifyTransactionSign(tx, verifyPreHashCount, txBlockHash, txHashStr))
			{
				ERRORLOG("VerifyTransactionSign");
				bRollback = true;
				return false;
			}

			if (verifyPreHashCount < g_MinNeedVerifyPreHashCount)
			{
				ERRORLOG("verifyPreHashCount < g_MinNeedVerifyPreHashCount");
				bRollback = true;
				return false;
			}
		}

		// 获取交易类型
		// bool bIsRedeem = false;
		std::string redempUtxoStr;
		for (int i = 0; i < cblock.txs_size(); i++)
		{
			CTransaction transaction = cblock.txs(i);
			if ( CheckTransactionType(transaction) == kTransactionType_Tx)
			{
				CTransaction copyTx = transaction;

				nlohmann::json txExtra = nlohmann::json::parse(copyTx.extra());
				std::string txType = txExtra["TransactionType"].get<std::string>();

				if (txType == TXTYPE_REDEEM)
				{
					// bIsRedeem = true;

					nlohmann::json txInfo = txExtra["TransactionInfo"].get<nlohmann::json>();
					redempUtxoStr = txInfo["RedeemptionUTXO"].get<std::string>();
				}
			}
		}
		//{{ Redeem time is more than 30 days, 20201214
		if (!redempUtxoStr.empty() && cblock.height() > g_compatMinHeight)
		{
			int result = IsMoreThan30DaysForRedeem(redempUtxoStr);
			if (result != 0)
			{
				ERRORLOG("Redeem time is less than 30 days!");
				bRollback = true;
				return false;
			}
			else
			{
				DEBUGLOG("Redeem time is more than 30 days!");
			}
		}
		//}}

		// 验证签名公钥和base58地址是否一致
		std::vector< std::string > signBase58Addrs;
		for (int i = 0; i < cblock.txs_size(); i++)
		{
			CTransaction transaction = cblock.txs(i);
			if ( CheckTransactionType(transaction) == kTransactionType_Tx)
			{
				// 取出所有签名账号的base58地址
				for (int k = 0; k < transaction.signprehash_size(); k++) 
                {
                    char buf[2048] = {0};
                    size_t buf_len = sizeof(buf);
                    GetBase58Addr(buf, &buf_len, 0x00, transaction.signprehash(k).pub().c_str(), transaction.signprehash(k).pub().size());
					std::string bufStr(buf);
					signBase58Addrs.push_back( bufStr );
                }
			}
		}

		std::vector<std::string> txOwners;
		uint64_t packageFee = 0;
		uint64_t signFee = 0;
		for (int i = 0; i < cblock.txs_size(); i++)
		{
			CTransaction transaction = cblock.txs(i);
			if ( CheckTransactionType(transaction) == kTransactionType_Tx)
			{
				SplitString(tx.txowner(), txOwners, "_");
				if (txOwners.size() < 1)
				{
					ERRORLOG("txOwners error!");
					bRollback = true;
					return false;
				}

				nlohmann::json extra = nlohmann::json::parse(tx.extra());
				packageFee = extra["PackageFee"].get<uint64_t>();
				signFee = extra["SignFee"].get<uint64_t>();
			}
		}

		for (int i = 0; i < cblock.txs_size(); i++)
		{
			CTransaction transaction = cblock.txs(i);
			if ( CheckTransactionType(transaction) == kTransactionType_Fee)
			{
				// 签名账号的数量和vout的数量不一致，错误
				if( signBase58Addrs.size() != (size_t)transaction.vout_size() )
				{
					ERRORLOG("signBase58Addrs.size() != (size_t)transaction.vout_size()");
					bRollback = true;
					return false;
				}

				// base58地址不一致，错误
				for(int l = 0; l < transaction.vout_size(); l++)
				{
					CTxout txout = transaction.vout(l);	
					auto iter = find(signBase58Addrs.begin(), signBase58Addrs.end(), txout.scriptpubkey());
					if( iter == signBase58Addrs.end() )
					{
						ERRORLOG("iter == signBase58Addrs.end()");
						bRollback = true;
						return false;
					}

					if (txout.value() < 0)
					{
						ERRORLOG("vout error !");
						bRollback = true;
						return false;
					}

					if (txOwners.end() != find(txOwners.begin(), txOwners.end(), txout.scriptpubkey()))
					{
						if (txout.value() != 0)
						{
							bRollback = true;
							ERRORLOG("txout.value() != 0");
							return false;
						}
					}
					else
					{
						if ((uint64_t)txout.value() != signFee && (uint64_t)txout.value() != packageFee)
						{
							ERRORLOG("SignFee or packageFee error !");
							bRollback = true;
							return false;
						}
					}
				}
			}
			else if ( CheckTransactionType(transaction) == kTransactionType_Award )
			{
				uint64_t awardAmountTotal = 0;
				for (auto & txout : transaction.vout())
				{
					// 不使用uint64 是为了防止有负值的情况
					int64_t value = txout.value();
					std::string voutAddr = txout.scriptpubkey();

					if (cblock.height() > g_compatMinHeight)
					{		
						// 发起方账号奖励为0
						if (txOwners.end() != find(txOwners.begin(), txOwners.end(), voutAddr))
						{
							if (value != 0)
							{
								ERRORLOG("Award error !");
								bRollback = true;
								return false;
							}
						}
						else
						{
							// 奖励为负值，或者大于单笔最高奖励值的时候，错误，返回
							if (value < 0 || (uint64_t)value > g_MaxAwardTotal)
							{
								ERRORLOG("Award error !");
								bRollback = true;
								return false;
							}
							else if (value == 0)
							{
								for (int i = 0; i < cblock.txs_size(); i++)
								{
									CTransaction transaction = cblock.txs(i);
									uint32_t count = 0;
									if ( CheckTransactionType(transaction) == kTransactionType_Award)
									{
										for (auto & txout : transaction.vout())
										{
											if (txout.value() == 0)
											{
												count++;
											}
										}

										if (count > 1)
										{
											bRollback = true;
											ERRORLOG("check award count > 1");
											return false;
										}
									}
								}
							}

							nlohmann::json txExtra;
							try
							{
								txExtra = nlohmann::json::parse(tx.extra());
							}
							catch(const std::exception& e)
							{
								std::cerr << e.what() << '\n';
								bRollback = true;
								ERRORLOG("json::parse error");
								return false;
							}
							
							for (nlohmann::json::iterator it = txExtra.begin(); it != txExtra.end(); ++it) 
							{
								if (voutAddr == it.key())
								{
									auto iter = addrAwards.find(voutAddr);
									if (iter == addrAwards.end())
									{
										ERRORLOG("Transaction award error !");
										bRollback = true;
										return false;
									}
									else
									{
										if ((uint64_t)value != iter->second)
										{
											ERRORLOG("Transaction award error !");
											bRollback = true;
											return false;
										}
									}
								}
							}
						}
					}
					awardAmountTotal += txout.value();
				}

				if (awardAmountTotal > g_MaxAwardTotal)
				{
					ERRORLOG("awardAmountTotal error !");
					bRollback = true;
					return false;
				}
			}
		}
	}


	// 共识数不能小于g_MinNeedVerifyPreHashCount
	if (cblock.height() > g_compatMinHeight)
	{
		for(auto & tx : cblock.txs())
		{
			if (CheckTransactionType(tx) == kTransactionType_Tx)
			{
				std::vector<std::string> txownersTmp = TxHelper::GetTxOwner(tx);

				for (auto & txout : tx.vout())
				{
					if (txout.value() <= 0 && txownersTmp.end() == find(txownersTmp.begin(), txownersTmp.end(), txout.scriptpubkey()))
					{
						// 交易接收方接收金额不能为0
						ERRORLOG("Tx vout error !");
						bRollback = true;
						return false;
					}
					else if (txout.value() < 0 && txownersTmp.end() != find(txownersTmp.begin(), txownersTmp.end(), txout.scriptpubkey()))
					{
						// 交易发起方剩余资产可以为0.但不能小于0
						ERRORLOG("Tx vout error !");
						bRollback = true;
						return false;
					}
				}
			}
			else if ( CheckTransactionType(tx) == kTransactionType_Fee)
			{
				if (tx.vout_size() < g_MinNeedVerifyPreHashCount)
				{
					ERRORLOG("The number of signers is not less than {} !", g_MinNeedVerifyPreHashCount);
					bRollback = true;
					return false;
				}
			}
		}
	}

	return true;
}


std::string CalcBlockHeaderMerkle(const CBlock & cblock)
{
	std::string merkle;
	if (cblock.txs_size() == 0)
	{
		return merkle;
	}

	std::vector<std::string> vTxHashs;
	for (int i = 0; i != cblock.txs_size(); ++i)
	{
		CTransaction tx = cblock.txs(i);
		vTxHashs.push_back(tx.hash());
	}

	unsigned int j = 0, nSize;
    for (nSize = cblock.txs_size(); nSize > 1; nSize = (nSize + 1) / 2)
	{
        for (unsigned int i = 0; i < nSize; i += 2)
		{
            unsigned int i2 = MIN(i+1, nSize-1);

			std::string data1 = vTxHashs[j + i];
			std::string data2 = vTxHashs[j + i2];
			data1 = getsha256hash(data1);
			data2 = getsha256hash(data2);

			vTxHashs.push_back(getsha256hash(data1 + data2));
        }

        j += nSize;
    }

	merkle = vTxHashs[vTxHashs.size() - 1];

	return merkle;
}

void CalcBlockMerkle(CBlock & cblock)
{
	if (cblock.txs_size() == 0)
	{
		return;
	}

	cblock.set_merkleroot(CalcBlockHeaderMerkle(cblock));
}

CBlock CreateBlock(const CTransaction & tx, const std::shared_ptr<TxMsg>& SendTxMsg)
{
	CBlock cblock;

	uint64_t time = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
    cblock.set_time(time);
	cblock.set_version(0);

	nlohmann::json txExtra = nlohmann::json::parse(tx.extra());
	int NeedVerifyPreHashCount = txExtra["NeedVerifyPreHashCount"].get<int>();
	std::string txType = txExtra["TransactionType"].get<std::string>();

	// 将签名数通过Json格式放入块扩展信息
	nlohmann::json blockExtra;
	blockExtra["NeedVerifyPreHashCount"] = NeedVerifyPreHashCount;

	if (txType == TXTYPE_TX)
	{
		blockExtra["TransactionType"] = TXTYPE_TX;
	}
	else if (txType == TXTYPE_PLEDGE)
	{
		nlohmann::json txInfoTmp = txExtra["TransactionInfo"].get<nlohmann::json>();

		nlohmann::json blockTxInfo;
		blockTxInfo["PledgeAmount"] = txInfoTmp["PledgeAmount"].get<int>();

		blockExtra["TransactionType"] = TXTYPE_PLEDGE;
		blockExtra["TransactionInfo"] = blockTxInfo;
	}
	else if (txType == TXTYPE_REDEEM)
	{
		nlohmann::json txInfoTmp = txExtra["TransactionInfo"].get<nlohmann::json>();

		nlohmann::json blockTxInfo;
		blockTxInfo["RedeemptionUTXO"] = txInfoTmp["RedeemptionUTXO"].get<std::string>();

		blockExtra["TransactionType"] = TXTYPE_REDEEM;
		blockExtra["TransactionInfo"] = blockTxInfo;
	}
	else if(txType == TXTYPE_CONTRACT_DEPLOY)
	{
		blockExtra["TransactionType"] = TXTYPE_CONTRACT_DEPLOY;
	}
	else if(txType == TXTYPE_CONTRACT_EXECUTE)
	{
		blockExtra["TransactionType"] = TXTYPE_CONTRACT_EXECUTE;
	}

	cblock.set_extra( blockExtra.dump() );

    int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(CreateBlock) TransactionInit failed !");
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	std::string prevBlockHash = SendTxMsg->prevblkhash();
	unsigned int prevBlockHeight = 0;
	if (0 != pRocksDb->GetBlockHeightByBlockHash(txn, prevBlockHash, prevBlockHeight))
	{
		// 父块不存在, 不建块
		cblock.clear_hash();
		return cblock;
	}

	// 要加的块的高度
	unsigned int cblockHeight = ++prevBlockHeight;

	unsigned int myTop = 0;
	pRocksDb->GetBlockTop(txn, myTop);
	if ( (myTop  > 9) && (myTop - 9 > cblockHeight))
	{
		cblock.clear_hash();
		return cblock;
	}
	else if (myTop + 1 < cblockHeight)
	{
		cblock.clear_hash();
		return cblock;
	}

	std::string bestChainHash;
	db_status = pRocksDb->GetBestChainHash(txn, bestChainHash);
    if (db_status != 0) 
	{
		ERRORLOG("(CreateBlock) GetBestChainHash failed db_status:{}!", db_status);
    }
	if (bestChainHash.size() == 0)
	{
		cblock.set_prevhash(std::string(64, '0'));
		cblock.set_height(0);
	}
	else
	{
		cblock.set_prevhash(bestChainHash);
		unsigned int preheight = 0;
		db_status = pRocksDb->GetBlockHeightByBlockHash(txn, bestChainHash, preheight);
		if (db_status != 0) 
		{
			ERRORLOG("CreateBlock GetBlockHeightByBlockHash");
		}
		cblock.set_height(preheight + 1);
	}

	CTransaction * tx0 = cblock.add_txs();
	*tx0 = tx;

	if (ENCOURAGE_TX) 
	{
		DEBUGLOG("Crreate Encourage TX ... ");

		CTransaction workTx = CreateWorkTx(*tx0);
		if (workTx.hash().empty())
		{
			cblock.clear_hash();
			return cblock;
		}
		CTransaction * tx1 = cblock.add_txs();
		*tx1 = workTx;

        if (get_extra_award_height()) {
            DEBUGLOG("Crreate Encourage TX 2 ... ");
            CTransaction workTx2 = CreateWorkTx(*tx0, true, SendTxMsg);
			if (workTx2.hash().empty())
			{
				cblock.clear_hash();
				return cblock;
			}
            CTransaction * txadd2 = cblock.add_txs();
            *txadd2 = workTx2;
        }
	}

	CalcBlockMerkle(cblock);

	std::string serBlockHeader = cblock.SerializeAsString();
	cblock.set_hash(getsha256hash(serBlockHeader));

	return cblock;
}

bool AddBlock(const CBlock & cblock, bool isSync)
{
	unsigned int preheight;
    int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(AddBlock) TransactionInit failed !");
		return false;
	}

	bool bRollback = true;
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, bRollback);
	};

	db_status = pRocksDb->GetBlockHeightByBlockHash(txn, cblock.prevhash(), preheight);
	DEBUGLOG("AddBlock GetBlockHeightByBlockHash db_status:{}", db_status);
    if (db_status != 0) {
		bRollback = true;
        return false;
    }

	CBlockHeader block;
	block.set_hash(cblock.hash());
	block.set_prevhash(cblock.prevhash());
	block.set_time(cblock.time());
	block.set_height(preheight +1);

	unsigned int top = 0;
	DEBUGLOG("AddBlock GetBlockTop", db_status);
	if (pRocksDb->GetBlockTop(txn, top) != 0)
	{
		ERRORLOG("AddBlock GetBlockTop ret != 0");
		bRollback = true;
		return false;
	}

	//更新top和BestChain
	bool is_mainblock = false;
	if (block.height() > top)  
	{
		is_mainblock = true;
		db_status = pRocksDb->SetBlockTop(txn, block.height());
        if (db_status != 0) {
			bRollback = true;
            return false;
        }
		db_status = pRocksDb->SetBestChainHash(txn, block.hash());
        if (db_status != 0) 
		{
			bRollback = true;
            return false;
        }
	}
	else if (block.height() == top)
	{
		std::string strBestChainHash;
		if (pRocksDb->GetBestChainHash(txn, strBestChainHash) != 0)
		{
			bRollback = true;
			return false;
		}

		std::string strBestChainHeader;
		if (pRocksDb->GetBlockByBlockHash(txn, strBestChainHash, strBestChainHeader) != 0)
		{
			bRollback = true;
			return false;
		}

		CBlock bestChainBlockHeader;
		bestChainBlockHeader.ParseFromString(strBestChainHeader);

		if (cblock.time() < bestChainBlockHeader.time())
		{
			is_mainblock = true;
			db_status = pRocksDb->SetBestChainHash(txn, block.hash());
            if (db_status != 0) 
			{
				bRollback = true;
                return false;
            }
		}
	}
	else if(block.height() < top)
	{
		std::string main_hash;
		pRocksDb->GetBlockHashByBlockHeight(txn, block.height(), main_hash);
		std::string main_block_str;
		if (pRocksDb->GetBlockByBlockHash(txn, main_hash, main_block_str) != 0)
		{
			bRollback = true;
			return false;
		}
		CBlock main_block;
		main_block.ParseFromString(main_block_str);	
		if (cblock.time() < main_block.time())
		{
			is_mainblock = true;
		}
	}

	// uint64_t t3 = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();


	db_status = pRocksDb->SetBlockHeightByBlockHash(txn, block.hash(), block.height());
	DEBUGLOG("AddBlock SetBlockHeightByBlockHash db_status:{}", db_status);

    if (db_status != 0) 
	{
		bRollback = true;
        return false;
    }
	db_status = pRocksDb->SetBlockHashByBlockHeight(txn, block.height(), block.hash(), is_mainblock);
	DEBUGLOG("AddBlock SetBlockHashByBlockHeight db_status:{}", db_status);

    if (db_status != 0) 
	{
		bRollback = true;
        return false;
    }
	db_status = pRocksDb->SetBlockHeaderByBlockHash(txn, block.hash(), block.SerializeAsString());
	DEBUGLOG("AddBlock SetBlockHeaderByBlockHash db_status:{}", db_status);
    if (db_status != 0) 
	{
		bRollback = true;
        return false;
    }
	db_status = pRocksDb->SetBlockByBlockHash(txn, block.hash(), cblock.SerializeAsString());
	DEBUGLOG("AddBlock SetBlockByBlockHash db_status:{}", db_status);
    if (db_status != 0) 
	{
		bRollback = true;
        return false;
    }

	// 判断交易是否是特殊交易
	bool isPledge = false;
	bool isRedeem = false;
	std::string redempUtxoStr;

	nlohmann::json extra = nlohmann::json::parse(cblock.extra());
	std::string txType = extra["TransactionType"].get<std::string>();
	if (txType == TXTYPE_PLEDGE)
	{
		isPledge = true;
	}
	else if (txType == TXTYPE_REDEEM)
	{
		isRedeem = true;
		nlohmann::json txInfo = extra["TransactionInfo"].get<nlohmann::json>();
		redempUtxoStr = txInfo["RedeemptionUTXO"].get<std::string>();
	}
	
	// 计算支出的总燃油费
	uint64_t totalGasFee = 0;
	for (int txCount = 0; txCount < cblock.txs_size(); txCount++)
	{
		CTransaction tx = cblock.txs(txCount);
		if ( CheckTransactionType(tx) == kTransactionType_Fee)
		{
			for (int j = 0; j < tx.vout_size(); j++)
			{
				CTxout txout = tx.vout(j);
				totalGasFee += txout.value();
			}
		}
	}

	if(totalGasFee == 0 && !isRedeem)
	{
		ca_console redColor(kConsoleColor_Red, kConsoleColor_Black, true);
		ERRORLOG("tx sign GasFee is 0! AddBlock failed! ");

		bRollback = true;
		return false;
	}

	for (int i = 0; i < cblock.txs_size(); i++)
	{
		CTransaction tx = cblock.txs(i);
		bool isTx = false;
		if (CheckTransactionType(tx) == kTransactionType_Tx)
		{
			isTx = true;
		}

		for (int j = 0; j < tx.vout_size(); j++)
		{
			CTxout txout = tx.vout(j);

			if (isPledge && isTx)
			{
				if ( !txout.scriptpubkey().compare(VIRTUAL_ACCOUNT_PLEDGE) )
				{
					db_status = pRocksDb->SetPledgeAddresses(txn, TxHelper::GetTxOwner(tx)[0]);
					if (db_status != 0 && db_status != pRocksDb->ROCKSDB_IS_EXIST)
					{
						bRollback = true;
						return false;
					}

					db_status = pRocksDb->SetPledgeAddressUtxo(txn, TxHelper::GetTxOwner(tx)[0], tx.hash()); 
					if (db_status != 0)
					{
						bRollback = true;
						return false;
					}
				}
			}

			if ( txout.scriptpubkey().compare(VIRTUAL_ACCOUNT_PLEDGE) )
			{
				db_status = pRocksDb->SetUtxoHashsByAddress(txn, txout.scriptpubkey(), tx.hash());
				if (db_status != 0 && db_status != pRocksDb->ROCKSDB_IS_EXIST) 
				{
					bRollback = true;
					return false;
				}	
			}
		}

		db_status = pRocksDb->SetTransactionByHash(txn, tx.hash(), tx.SerializeAsString());
		DEBUGLOG("AddBlock SetTransactionByHash db_status:{}", db_status);
        if (db_status != 0) {
			bRollback = true;
            return false;
        }
		db_status = pRocksDb->SetBlockHashByTransactionHash(txn, tx.hash(), cblock.hash());
		DEBUGLOG("AddBlock SetBlockHashByTransactionHash db_status:{}", db_status);
        if (db_status != 0) {
			bRollback = true;
            return false;
        }

		std::vector<std::string> vPledgeUtxoHashs;
		if (isRedeem && isTx)
		{
			db_status = pRocksDb->GetPledgeAddressUtxo(txn, TxHelper::GetTxOwner(tx)[0], vPledgeUtxoHashs);
			if (db_status != 0) 
			{
				bRollback = true;
				return false;
			}			
		}

		// 判断交易的vin中是否有质押产生的正常utxo部分
		nlohmann::json extra = nlohmann::json::parse(tx.extra());
		std::string txType = extra["TransactionType"];
		std::string redempUtxoStr;
		uint64_t packageFee = 0;
		if (txType == TXTYPE_REDEEM)
		{
			nlohmann::json txInfo = extra["TransactionInfo"].get<nlohmann::json>();
			redempUtxoStr = txInfo["RedeemptionUTXO"].get<std::string>();
			packageFee = extra["PackageFee"].get<uint64_t>();
		}

		std::vector<CTxin> txVins;
		uint64_t vinAmountTotal = 0;
		uint64_t voutAmountTotal = 0;

		for (auto & txin : tx.vin())
		{
			txVins.push_back(txin);
		}

		if (txType == TXTYPE_REDEEM)
		{
			for (auto iter = txVins.begin(); iter != txVins.end(); ++iter)
			{
				if (iter->prevout().hash() == redempUtxoStr)
				{
					txVins.erase(iter);
					break;
				}
			}
		}

		std::vector<std::string> utxos;
		for (auto & txin : txVins)
		{
			if (utxos.end() != find(utxos.begin(), utxos.end(), txin.prevout().hash()))
			{
				continue;
			}

			std::string txinAddr = GetBase58Addr(txin.scriptsig().pub());
			vinAmountTotal += TxHelper::GetUtxoAmount(txin.prevout().hash(), txinAddr);
			utxos.push_back(txin.prevout().hash());
		}

		bool bIsUsed = false;
		if (CheckTransactionType(tx) == kTransactionType_Tx && txType == TXTYPE_REDEEM)
		{
			for (int txCount = 0; txCount < cblock.txs_size(); txCount++)
			{
				CTransaction txTmp = cblock.txs(txCount);
				if (CheckTransactionType(txTmp) != kTransactionType_Award)
				{
					for (auto & txout : txTmp.vout())
					{
						voutAmountTotal += txout.value();
					}
				}
			}

			if (voutAmountTotal != vinAmountTotal)
			{
				uint64_t usable = TxHelper::GetUtxoAmount(redempUtxoStr, TxHelper::GetTxOwner(tx)[0]);
				uint64_t redeemAmount = TxHelper::GetUtxoAmount(redempUtxoStr,VIRTUAL_ACCOUNT_PLEDGE);
				if (voutAmountTotal == vinAmountTotal + usable + redeemAmount)
				{
					// 本交易使用了质押utxo的正常部分
					bIsUsed = true;
				}
				else if (voutAmountTotal == vinAmountTotal + redeemAmount + packageFee)
				{
					bIsUsed = false;
				}
				else
				{
					if (cblock.height() > g_compatMinHeight)
					{
						bRollback = true;
						return false;
					}
				}
				
			}
		}

		// vin
		std::vector<std::string> fromAddrs;
		if (CheckTransactionType(tx) == kTransactionType_Tx)
		{
			// 解质押交易有重复的UTXO,去重
			std::set<std::pair<std::string, std::string>> utxoAddrSet; 
			for (auto & txin : tx.vin())
			{
				std::string addr = GetBase58Addr(txin.scriptsig().pub());

				// 交易记录
				if ( 0 != pRocksDb->SetAllTransactionByAddress(txn, addr, tx.hash()))
				{
					bRollback = true;
					return false;
				}
				fromAddrs.push_back(addr);

				std::vector<std::string> utxoHashs;
				db_status = pRocksDb->GetUtxoHashsByAddress(txn, addr, utxoHashs);
				if (db_status != 0) 
				{
					bRollback = true;
					return false;
				}

				// 在所有utxo中查找vin使用的utxo是否存在
				if (utxoHashs.end() == find(utxoHashs.begin(), utxoHashs.end(), txin.prevout().hash() ) )
				{
					// 在可使用的utxo找不到，则判断是否为解质押的utxo
					if (txin.prevout().hash() != redempUtxoStr)
					{
						bRollback = true;
						return false;
					}
					else
					{
						continue;
					}
				}

				std::pair<std::string, std::string> utxoAddr = make_pair(txin.prevout().hash(), addr);
				utxoAddrSet.insert(utxoAddr);
			}

			for (auto & utxoAddr : utxoAddrSet) 
			{
				std::string utxo = utxoAddr.first;
				std::string addr = utxoAddr.second;

				std::string txRaw;
				if (0 != pRocksDb->GetTransactionByHash(txn, utxo, txRaw) )
				{
					bRollback = true;
					return false;
				}

				CTransaction utxoTx;
				utxoTx.ParseFromString(txRaw);

				nlohmann::json extra = nlohmann::json::parse(tx.extra());
				std::string txType = extra["TransactionType"];
				
				if (txType == TXTYPE_PLEDGE && !bIsUsed && utxo == redempUtxoStr)
				{
					continue;
				}

				db_status = pRocksDb->RemoveUtxoHashsByAddress(txn, addr, utxo);
				if (db_status != 0)
				{
					bRollback = true;
					return false;
				}

				// vin减utxo
				uint64_t amount = TxHelper::GetUtxoAmount(utxo, addr);
				int64_t balance = 0;
				db_status = pRocksDb->GetBalanceByAddress(txn, addr, balance);
				if (db_status != 0) 
				{
					ERRORLOG("AddBlock:GetBalanceByAddress");
					bRollback = true;
					return false;
				}

				balance -= amount;

				if(balance < 0)
				{
					ERRORLOG("balance < 0");
					bRollback = true;
					return false;
				}

				db_status = pRocksDb->SetBalanceByAddress(txn, addr, balance);
				if (db_status != 0) 
				{
					bRollback = true;
					return false;
				}
			}

			if (isRedeem)
			{
				std::string addr = TxHelper::GetTxOwner(tx)[0];
				db_status = pRocksDb->RemovePledgeAddressUtxo(txn, addr, redempUtxoStr);
				if (db_status != 0)
				{
					bRollback = true;
					return false;
				}
				std::vector<string> utxoes;
				db_status = pRocksDb->GetPledgeAddressUtxo(txn, addr, utxoes);
				if (db_status != 0)
				{
					bRollback = true;
					return false;
				}
				if(utxoes.size() == 0)
				{
					db_status = pRocksDb->RemovePledgeAddresses(txn, addr);
					if (db_status != 0)
					{
						bRollback = true;
						return false;
					}
				}
			}
		}

		// vout
		if ( CheckTransactionType(tx) == kTransactionType_Tx)
		{	
			for (int j = 0; j < tx.vout_size(); j++)
			{
				//vout加余额
				CTxout txout = tx.vout(j);
				std::string vout_address = txout.scriptpubkey();
				int64_t balance = 0;
				db_status = pRocksDb->GetBalanceByAddress(txn, vout_address, balance);
				if (db_status != 0) 
				{
					INFOLOG("AddBlock:GetBalanceByAddress");
				}
				balance += txout.value();
				db_status = pRocksDb->SetBalanceByAddress(txn, vout_address, balance);
				if (db_status != 0) 
				{
					bRollback = true;
					return false;
				}

				if (isRedeem && 
					tx.vout_size() == 2 && 
					tx.vout(0).scriptpubkey() == tx.vout(1).scriptpubkey())
				{
					if (j == 0)
					{
						db_status = pRocksDb->SetAllTransactionByAddress(txn, txout.scriptpubkey(), tx.hash());
						if (db_status != 0) {
							bRollback = true;
							return false;
						}
					}
				}
				else
				{
					// 交易发起方已经记录
					if (fromAddrs.end() != find( fromAddrs.begin(), fromAddrs.end(), txout.scriptpubkey()))
					{
						continue;
					}

					db_status = pRocksDb->SetAllTransactionByAddress(txn, txout.scriptpubkey(), tx.hash());
					if (db_status != 0) {
						bRollback = true;
						return false;
					}
				}
			}
		}
		else
		{
			for (int j = 0; j < tx.vout_size(); j++)
			{
				CTxout txout = tx.vout(j);
				int64_t value = 0;
				db_status = pRocksDb->GetBalanceByAddress(txn, txout.scriptpubkey(), value);
				if (db_status != 0) {
					INFOLOG("AddBlock:GetBalanceByAddress");
				}
				value += txout.value();
				db_status = pRocksDb->SetBalanceByAddress(txn, txout.scriptpubkey(), value);
				if (db_status != 0) {
					bRollback = true;
					return false;
				}
				db_status = pRocksDb->SetAllTransactionByAddress(txn, txout.scriptpubkey(), tx.hash());
				if (db_status != 0) {
					bRollback = true;
					return false;
				}
			}
		}

		// 累加额外奖励
		if ( CheckTransactionType(tx) == kTransactionType_Award)
		{
			for (int j = 0; j < tx.vout_size(); j++)
			{
				CTxout txout = tx.vout(j);

				uint64_t awardTotal = 0;
				pRocksDb->GetAwardTotal(txn, awardTotal);

				awardTotal += txout.value();
				if ( 0 != pRocksDb->SetAwardTotal(txn, awardTotal) )
				{
					bRollback = true;
					return false;
				}

				if (txout.value() >= 0)
				{
					// 累加账号的额外奖励总值
					uint64_t addrAwardTotal = 0;
					if (0 != pRocksDb->GetAwardTotalByAddress(txn, txout.scriptpubkey(), addrAwardTotal))
					{
						ERRORLOG("(AddBlock) GetAwardTotalByAddress failed !");
					}
					addrAwardTotal += txout.value();

					if (0 != pRocksDb->SetAwardTotalByAddress(txn, txout.scriptpubkey(), addrAwardTotal))
					{
						ERRORLOG("(AddBlock) SetAwardTotalByAddress failed !");
						bRollback = true;
						return false;
					}
				}

				// 累加账号的签名次数
				uint64_t signSum = 0;
				if (0 != pRocksDb->GetSignNumByAddress(txn, txout.scriptpubkey(), signSum))
				{
					ERRORLOG("(AddBlock) GetSignNumByAddress failed !");
				}
				++signSum;

				if (0 != pRocksDb->SetSignNumByAddress(txn, txout.scriptpubkey(), signSum))
				{
					ERRORLOG("(AddBlock) SetSignNumByAddress failed !");
					bRollback = true;
					return false;
				}
			}
		}

		// 处理部署合约类型交易
		TxHelper::DeployContractToDB(tx, pRocksDb, txn);

		// 处理执行合约交易类型
		TxHelper::ExecuteContractToDB(tx, pRocksDb, txn);		
	}
	DEBUGLOG("AddBlock TransactionCommit");
	if( pRocksDb->TransactionCommit(txn) )
	{
		ERRORLOG("(Addblock) TransactionCommit failed !");
		bRollback = true;
		return false;
	}

	//{{ Delete pending transaction, 20201215
	for (int i = 0; i < cblock.txs_size(); i++)
	{
		CTransaction tx = cblock.txs(i);
		if (CheckTransactionType(tx) == kTransactionType_Tx)
		{
			std::vector<std::string> txOwnerVec;
			SplitString(tx.txowner(), txOwnerVec, "_");
			int result = MagicSingleton<TxVinCache>::GetInstance()->Remove(tx.hash(), txOwnerVec);
			if (result == 0)
			{
				std::cout << "Remove pending transaction in Cache " << tx.hash() << " from ";
				for_each(txOwnerVec.begin(), txOwnerVec.end(), [](const string& owner){ cout << owner << " "; });
				std::cout << std::endl;
			}
		}
	}
	//}}

	//{{ Update the height of the self node, 20210323 Liu
	Singleton<PeerNode>::get_instance()->set_self_chain_height();
	//}}
	
	//{{ Check http callback, 20210324 Liu
	if (Singleton<Config>::get_instance()->HasHttpCallback())
	{
		if (MagicSingleton<CBlockHttpCallback>::GetInstance()->IsRunning())
		{
			MagicSingleton<CBlockHttpCallback>::GetInstance()->AddBlock(cblock);
		}
	}
	//}}
	return true;
}

void CalcTransactionHash(CTransaction & tx)
{
	std::string hash = tx.hash();
	if (hash.size() != 0)
	{
		return;
	}

	CTransaction copyTx = tx;

	copyTx.clear_signprehash();

	std::string serTx = copyTx.SerializeAsString();

	hash = getsha256hash(serTx);
	tx.set_hash(hash);
}

bool ContainSelfSign(const CTransaction & tx)
{
	for (int i = 0; i != tx.signprehash_size(); ++i)
	{
		CSignPreHash signPreHash = tx.signprehash(i);

		char pub[2045] = {0};
		size_t pubLen = sizeof(pub);
		GetBase58Addr(pub, &pubLen, 0x00, signPreHash.pub().c_str(), signPreHash.pub().size());

		if (g_AccountInfo.isExist(pub))
		{
			INFOLOG("Signer [{}] Has Signed !!!", pub);
			return true;
		}
	}
	return false;
}

bool VerifySignPreHash(const CSignPreHash & signPreHash, const std::string & serTx)
{
	int pubLen = signPreHash.pub().size();
	char * rawPub = new char[pubLen * 2 + 2]{0};
	encode_hex(rawPub, signPreHash.pub().c_str(), pubLen);

	ECDSA<ECP, SHA1>::PublicKey publicKey;
	std::string sPubStr;
	sPubStr.append(rawPub, pubLen * 2);
	SetPublicKey(publicKey, sPubStr);

	delete [] rawPub;

	return VerifyMessage(publicKey, serTx, signPreHash.sign());
}

bool VerifyScriptSig(const CScriptSig & scriptSig, const std::string & serTx)
{
	std::string addr = GetBase58Addr(scriptSig.pub());

	int pubLen = scriptSig.pub().size();
	char * rawPub = new char[pubLen * 2 + 2]{0};
	encode_hex(rawPub, scriptSig.pub().c_str(), pubLen);

	ECDSA<ECP, SHA1>::PublicKey publicKey;
	std::string sPubStr;
	sPubStr.append(rawPub, pubLen * 2);
	SetPublicKey(publicKey, sPubStr);

	delete [] rawPub;

	return VerifyMessage(publicKey, serTx, scriptSig.sign());

	//===============
	// ECDSA<ECP, SHA1>::PublicKey publicKey;
	// std::string sPubStr = GetBase58Addr(scriptSig.pub());
	// SetPublicKey(publicKey, sPubStr);

	// return VerifyMessage(publicKey, serTx, scriptSig.sign());
}

bool isRedeemTx(const CTransaction &tx)
{
	// std::vector<std::string> txOwners = TxHelper::GetTxOwner(tx);
	// for (int i = 0; i < tx.vout_size(); ++i)
	// {
	// 	CTxout txout = tx.vout(i);
	// 	if (txOwners.end() == find(txOwners.begin(), txOwners.end(), txout.scriptpubkey()))
	// 	{
	// 		return false;
	// 	}
	// }
	// return true;

    auto extra = nlohmann::json::parse(tx.extra());
    std::string type = extra["TransactionType"].get<std::string>();
	if(type == TXTYPE_REDEEM)
	{
		return true;
	}
	return false;

}

bool VerifyTransactionSign(const CTransaction & tx, int & verifyPreHashCount, std::string & txBlockHash, std::string txHash)
{
	// TODO blockPrevHash 的
    int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(VerifyTransactionSign) TransactionInit failed !");
		return false;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	if ( CheckTransactionType(tx) == kTransactionType_Tx)
	{
		CTransaction copyTx = tx;
		for (int i = 0; i != copyTx.vin_size(); ++i)
		{
			CTxin * txin = copyTx.mutable_vin(i);
			txin->clear_scriptsig();
		}

		copyTx.clear_signprehash();
		copyTx.clear_hash();

		std::string serCopyTx = copyTx.SerializeAsString();
		size_t encodeLen = serCopyTx.size() * 2 + 1;
		unsigned char encode[encodeLen] = {0};
		memset(encode, 0, encodeLen);
		long codeLen = base64_encode((unsigned char *)serCopyTx.data(), serCopyTx.size(), encode);
		std::string encodeStr( (char *)encode, codeLen );

		std::string txHashStr = getsha256hash(encodeStr);
		txBlockHash = txHashStr;

		if(0 != txHashStr.compare(txHash))
		{
			ERRORLOG("接收到的txhash({})值 != 计算出的txhash({})值 ! ", txHashStr, txHash);
			return false;
		}
		//验证转账者签名
		for (int i = 0; i != tx.vin_size(); ++i)
		{
			CTxin txin = tx.vin(i);
			if (! VerifyScriptSig(txin.scriptsig(), txHash))
			{
				ERRORLOG("Verify TX InputSign failed ... ");
				return false;
			}
		}
		
		std::vector<std::string> owner_pledge_utxo;
		if (isRedeemTx(tx))
		{
			std::vector<std::string> txOwners = TxHelper::GetTxOwner(tx);
			for (auto i : txOwners)
			{
				std::vector<string> utxos;
				if (0 != pRocksDb->GetPledgeAddressUtxo(txn, i, utxos))
				{
					ERRORLOG("GetPledgeAddressUtxo failed ... ");
					return false;
				}

				std::for_each(utxos.begin(), utxos.end(),
						[&](std::string &s){ s = s + "_" + i;}
				);

				std::vector<std::string> tmp_owner = owner_pledge_utxo;
				std::sort(utxos.begin(), utxos.end());
				std::set_union(utxos.begin(),utxos.end(),tmp_owner.begin(),tmp_owner.end(),std::back_inserter(owner_pledge_utxo));
				std::sort(owner_pledge_utxo.begin(), owner_pledge_utxo.end());
			}
		}

		std::vector<std::string> owner_utxo_tmp = TxHelper::GetUtxosByAddresses(TxHelper::GetTxOwner(tx));
		std::sort(owner_utxo_tmp.begin(), owner_utxo_tmp.end());

		std::vector<std::string> owner_utxo;
		std::set_union(owner_utxo_tmp.begin(),owner_utxo_tmp.end(),owner_pledge_utxo.begin(),owner_pledge_utxo.end(),std::back_inserter(owner_utxo));
		std::sort(owner_utxo.begin(), owner_utxo.end());

		std::vector<std::string> tx_utxo = TxHelper::GetUtxosByTx(tx);
    	std::sort(tx_utxo.begin(), tx_utxo.end());

		std::vector<std::string> v_union;
		std::set_union(owner_utxo.begin(),owner_utxo.end(),tx_utxo.begin(),tx_utxo.end(),std::back_inserter(v_union));
		std::sort(v_union.begin(), v_union.end());
		//v_union.erase(unique(v_union.begin(), v_union.end()), v_union.end());

		// 解质押交易UTXO有重复,去重
		std::set<std::string> tmpSet(v_union.begin(), v_union.end());
		v_union.assign(tmpSet.begin(), tmpSet.end());

		std::vector<std::string> v_diff;
		std::set_difference(v_union.begin(),v_union.end(),owner_utxo.begin(),owner_utxo.end(),std::back_inserter(v_diff));

		if(v_diff.size() > 0)
		{
			ERRORLOG("VerifyTransactionSign fail. not have enough utxo");
			return false;
		}

		// 判断手机或RPC交易时，交易签名者是否是交易发起人
		std::set<std::string> txVinVec;
		for(auto & vin : tx.vin())
		{
			std::string prevUtxo = vin.prevout().hash();
			std::string strTxRaw;
			db_status = pRocksDb->GetTransactionByHash(txn, prevUtxo, strTxRaw);
			if (db_status != 0)
			{
				return false;
			}

			CTransaction prevTx;
			prevTx.ParseFromString(strTxRaw);
			if (prevTx.hash().size() == 0)
			{
				return false;
			}
			
			std::string vinBase58Addr = GetBase58Addr(vin.scriptsig().pub());
			txVinVec.insert(vinBase58Addr);

			std::vector<std::string> txOutVec;
			for (auto & txOut : prevTx.vout())
			{
				txOutVec.push_back(txOut.scriptpubkey());
			}

			if (std::find(txOutVec.begin(), txOutVec.end(), vinBase58Addr) == txOutVec.end())
			{
				return false;
			}
		}

		std::vector<std::string> txOwnerVec;
		SplitString(tx.txowner(), txOwnerVec, "_");

		std::vector<std::string> tmptxVinSet;
		tmptxVinSet.assign(txVinVec.begin(), txVinVec.end());

		std::vector<std::string> ivec(txOwnerVec.size() + tmptxVinSet.size());
		auto iVecIter = set_symmetric_difference(txOwnerVec.begin(), txOwnerVec.end(), tmptxVinSet.begin(), tmptxVinSet.end(), ivec.begin());
		ivec.resize(iVecIter - ivec.begin());

		if (ivec.size()!= 0)
		{
			return false;
		}
	}
	else
	{
		std::string strBestChainHash;
		db_status = pRocksDb->GetBestChainHash(txn, strBestChainHash);
        if (db_status != 0) 
		{
            return false;
        }
		if (strBestChainHash.size() != 0)
		{
			txBlockHash = COIN_BASE_TX_SIGN_HASH;
		}
	}
	//验证矿工签名
	for (int i = 0; i < tx.signprehash_size(); i++)
	{
		CSignPreHash signPreHash = tx.signprehash(i);
		if (! VerifySignPreHash(signPreHash, txBlockHash))
		{
			ERRORLOG("VerifyPreHashCount  VerifyMessage failed ... ");
			return false;
		}

		INFOLOG("Verify PreBlock HashSign succeed !!! VerifySignedCount[{}] -> {}", verifyPreHashCount + 1, txBlockHash.c_str());
		(verifyPreHashCount)++ ;
	}

	return true;
}

unsigned get_extra_award_height() 
{
    const unsigned MAX_AWARD = 500000; //TODO test 10
    unsigned award {0};
    unsigned top {0};
    int db_status = 0;
    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(get_extra_award_height) TransactionInit failed !");
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

    db_status = pRocksDb->GetBlockTop(txn, top);
    if (db_status != 0) 
	{
        return 0;
    }
    auto b_height = top;
    if (b_height <= MAX_AWARD) 
	{
        award = 2000;
    }
    return award;
}


bool IsNeedPackage(const CTransaction & tx)
{
	std::vector<std::string> owners = TxHelper::GetTxOwner(tx);
	return IsNeedPackage(owners);
}

bool IsNeedPackage(const std::vector<std::string> & fromAddr)
{
	bool bIsNeedPackage = true;
	for (auto &account : g_AccountInfo.AccountList)
	{
		if (fromAddr.end() != find(fromAddr.begin(), fromAddr.end(), account.first))
		{
			bIsNeedPackage = false;
		}
	}
	return bIsNeedPackage;
}


int new_add_ouput_by_signer(CTransaction &tx, bool bIsAward, const std::shared_ptr<TxMsg>& msg) 
{
    //获取共识数
	nlohmann::json extra = nlohmann::json::parse(tx.extra());
	int needVerifyPreHashCount = extra["NeedVerifyPreHashCount"].get<int>();
	int gasFee = extra["SignFee"].get<int>();
	int packageFee = extra["PackageFee"].get<int>();

    //额外奖励
    std::vector<int> award_list;
    int award = 2000000;
    getNodeAwardList(needVerifyPreHashCount, award_list, award);
    auto award_begin = award_list.begin();
    auto award_end = award_list.end();

	std::vector<std::string> signers;
    std::vector<double> online_time;
    std::vector<uint64_t> vec_award_total;
    std::vector<uint64_t> vec_sign_num;
	std::vector<uint64_t> num_arr;

	for (int i = 0; i < tx.signprehash_size(); i++)
	{
        if (bIsAward) 
		{
            CSignPreHash txpre = tx.signprehash(i);
            int pubLen = txpre.pub().size();
            char *rawPub = new char[pubLen * 2 + 2]{0};
            encode_hex(rawPub, txpre.pub().c_str(), pubLen);
            ECDSA<ECP, SHA1>::PublicKey publicKey;
            std::string sPubStr;
            sPubStr.append(rawPub, pubLen * 2);
            SetPublicKey(publicKey, sPubStr);
            delete [] rawPub;

            for (int j = 0; j < msg->signnodemsg_size(); j++) 
			{
                std::string ownPubKey;
                GetPublicKey(publicKey, ownPubKey);
                char SignerCstr[2048] = {0};
                size_t SignerCstrLen = sizeof(SignerCstr);
                GetBase58Addr(SignerCstr, &SignerCstrLen, 0x00, ownPubKey.c_str(), ownPubKey.size());
                auto psignNodeMsg = msg->signnodemsg(j);
                std::string signpublickey = psignNodeMsg.signpubkey();
                const char * signpublickeystr = signpublickey.c_str();

                if (!strcmp(SignerCstr, signpublickeystr)) 
				{
                    std::string temp_signature = psignNodeMsg.signmsg();
                    psignNodeMsg.clear_signmsg();
                    std::string message = psignNodeMsg.SerializeAsString();

                    auto re = VerifyMessage(publicKey, message, temp_signature);
                    if (!re) 
					{
                        ERRORLOG("VerifyMessage err!!!!!!!");
						return -1;
					} 
					else 
					{
                        signers.push_back(signpublickeystr);
                        online_time.push_back(psignNodeMsg.onlinetime());
						vec_award_total.push_back(psignNodeMsg.awardtotal());
						vec_sign_num.push_back(psignNodeMsg.signsum());
                    }
                }
            }
        } 
		else 
		{
			bool bIsLocal = false;    // 本节点发起的交易
			std::vector<std::string> txOwners = TxHelper::GetTxOwner(tx);
			if (txOwners.size() == 0) 
			{
				continue;
			}

			char buf[2048] = {0};
            size_t buf_len = sizeof(buf);

			CSignPreHash signPreHash = tx.signprehash(i);
			GetBase58Addr(buf, &buf_len, 0x00, signPreHash.pub().c_str(), signPreHash.pub().size());
			signers.push_back(buf);

			if (txOwners[0] == buf)
			{
				bIsLocal = true;
			}

			uint64_t num = 0;
			// 默认第一个签名为发起方的时候 
            if (i == 0)
            {
				if (bIsLocal)
				{
					num = 0;
				}
				else
				{
					num = packageFee;
				}
            }
            else
            {
                if (!bIsAward) 
				{
					num = gasFee;
                } 
				else 
				{
                    num = (*award_begin);
                    ++award_begin;
                    if (award_begin == award_end) break;
                }
            }

            num_arr.push_back(num);
        }
	}

    if (bIsAward) 
	{
        num_arr.push_back(0); //TODO
        a_award::AwardAlgorithm ex_award;
        if ( 0 != ex_award.Build(needVerifyPreHashCount, signers, online_time, vec_award_total, vec_sign_num) )
		{
			ERRORLOG("ex_award.Build error !");
			return -2;
		}
        auto dis_award = ex_award.GetDisAward();
        for (auto v : dis_award) 
		{
            CTxout * txout = tx.add_vout();
            txout->set_value(v.first);
            txout->set_scriptpubkey(v.second);
        }
        // ex_award.TestPrint(true);
        
		// 将签名节点的在线时长写入块中,用于校验奖励值
		nlohmann::json signNodeInfos;
		uint64_t count = 0;
		for (auto & nodeInfo : msg->signnodemsg())
		{
			nlohmann::json info;
			info["OnlineTime"] = nodeInfo.onlinetime();
			info["AwardTotal"] = nodeInfo.awardtotal();
			info["SignSum"] = nodeInfo.signsum();
			info["Addr"] = nodeInfo.signpubkey();

			signNodeInfos[count] = info;
			// std::string signAddr = GetBase58Addr(nodeInfo.signpubkey());
			// nlohmann::json info;
			// info["OnlineTime"] = nodeInfo.onlinetime();
			// info["AwardTotal"] = nodeInfo.awardtotal();
			// info["SignSum"] = nodeInfo.signsum();
			// signNodeInfos[signAddr] = info.dump();
			++count;
		}

		nlohmann::json awardTxExtra;
		try
		{
			awardTxExtra = nlohmann::json::parse(tx.extra());
		}
		catch(const std::exception& e)
		{
			std::cerr << e.what() << '\n';
		}
		awardTxExtra["OnlineTime"] = signNodeInfos;
		tx.set_extra(awardTxExtra.dump());
    } 
	else 
	{
        for (int i = 0; i < needVerifyPreHashCount; ++i)
        {
            CTxout * txout = tx.add_vout();
            txout->set_value(num_arr[i]);
            txout->set_scriptpubkey(signers[i]);
            INFOLOG("Transaction signer [{}]", signers[i].c_str());
        }
    }

	return 0;
}

CTransaction CreateWorkTx(const CTransaction & tx, bool bIsAward, const std::shared_ptr<TxMsg>& psignNodeMsg ) 
{
    CTransaction retTx;
    if (tx.vin_size() == 0) {
        return retTx;
    }
	std::string owner = TxHelper::GetTxOwner(tx)[0];
    g_AccountInfo.SetKeyByBs58Addr(g_privateKey, g_publicKey, owner.c_str());
    retTx = tx;

    retTx.clear_vin();
    retTx.clear_vout();
    retTx.clear_hash();


    int db_status = 0;
	(void)db_status;
    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(CreateWorkTx) TransactionInit failed !");
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

    unsigned int txIndex = 0;
    db_status = pRocksDb->GetTransactionTopByAddress(txn, retTx.txowner(), txIndex);
    if (db_status != 0) {
		ERRORLOG("(CreateWorkTx) GetTransactionTopByAddress failed db_status:{} !", db_status);
    }

    txIndex++;
    retTx.set_n(txIndex);

	uint64_t time = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
    retTx.set_time(time);
    retTx.set_ip(net_get_self_node_id());

	CTxin ownerTxin = tx.vin(0);

    CTxin * txin = retTx.add_vin();
    txin->set_nsequence(0xffffffff);
    CTxprevout * prevout = txin->mutable_prevout();
    prevout->set_n(0xffffffff);
    CScriptSig * scriptSig = txin->mutable_scriptsig();
    // scriptSig->set_sign("I am coinbase tx");
    // scriptSig->set_pub("");
	*scriptSig = ownerTxin.scriptsig();

    if (!bIsAward) 
	{
        prevout->set_hash(tx.hash());
    }

    if ( 0 != new_add_ouput_by_signer(retTx, bIsAward, psignNodeMsg) )
	{
		retTx.clear_hash();
		return retTx;
	}

    retTx.clear_signprehash();

    std::string serRetTx = retTx.SerializeAsString();
    std::string signature;
    std::string strPub;
    GetSignString(serRetTx, signature, strPub);

    for (int i = 0; i < retTx.vin_size(); i++)
    {
        CTxin * txin = retTx.mutable_vin(i);
        CScriptSig * scriptSig = txin->mutable_scriptsig();

        if (!bIsAward) 
		{
            scriptSig->set_sign(FEE_SIGN_STR);
        } 
		else 
		{
            scriptSig->set_sign(EXTRA_AWARD_SIGN_STR);
        }
        scriptSig->set_pub("");
    }

    CalcTransactionHash(retTx);

    return retTx;
}

void InitAccount(accountinfo *acc, const char *path)
{
	// 默认账户
	if (g_testflag)
	{
		g_InitAccount = "1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu";
	}
	else
	{
		g_InitAccount = "16psRip78QvUruQr9fMzr8EomtFS1bVaXk";
	}

	if(NULL == path)
	{
		g_AccountInfo.path =  OWNER_CERT_PATH;
	}
	else
	{
		g_AccountInfo.path =  path;
	}

	if('/' != g_AccountInfo.path[g_AccountInfo.path.size()-1]) 
	{
		g_AccountInfo.path += "/";
	}

	if(access(g_AccountInfo.path.c_str(), F_OK))
    {
        if(mkdir(g_AccountInfo.path.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH))
        {
            assert(false);
            return;
        }
    }

    if(!acc)
	{
		ERRORLOG("InitAccount Failed ...");
        return;
	}
	
    DIR *dir;
    struct dirent *ptr;

    if ((dir=opendir(g_AccountInfo.path.c_str())) == NULL)
    {
		ERRORLOG("OPEN DIR {} ERROR ..." , g_AccountInfo.path.c_str());
		return;
    }

    while ((ptr=readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)
		{
            continue;
		}
        else
        {
			DEBUGLOG("type[{}] filename[{}]", ptr->d_type, ptr->d_name);
            std::string bs58addr;
            if(0 == memcmp(ptr->d_name, OWNER_CERT_DEFAULT, strlen(OWNER_CERT_DEFAULT)))
            {
				std::string name(ptr->d_name);
				char *p = ptr->d_name + name.find('.') + 1;
				std::string ps(p);
                bs58addr.append(ptr->d_name, p + ps.find('.') - ptr->d_name );
                acc->GenerateKey(bs58addr.c_str(), true);
            }
            else
            {
				std::string name(ptr->d_name);
                bs58addr.append(ptr->d_name, ptr->d_name + name.find('.') - ptr->d_name);
                acc->GenerateKey(bs58addr.c_str(), false);
            }
        }
    }
	closedir(dir);

	if(!g_AccountInfo.GetAccSize())
    {
        g_AccountInfo.GenerateKey();
    }

	return;
}

std::string GetDefault58Addr()
{
	string sPubStr;
	GetPublicKey(g_publicKey, sPubStr);
	return GetBase58Addr(sPubStr);
}

/**
    vector最后一列为奖励总额
    amount总额为(共识数减一)乘(基数)
*/
int getNodeAwardList(int consensus, std::vector<int> &award_list, int amount, float coe) 
{
    using namespace std;

    //*奖励分配
    amount = amount*coe; //TODO
    consensus -= 1;
    consensus = consensus == 0 ? 1 : consensus;
    //auto award = consensus * base;
    int base {amount/consensus}; //平分资产 会有余
    int surplus = amount - base*consensus; //余
    award_list.push_back(amount);
    for (auto i = 1; i <= consensus; ++i) 
	{ //初始化 从1开始 除去总额
        award_list.push_back(base);
    }
    award_list[consensus] += surplus;

    //利率分配
    auto list_end_award {0};
    for (auto i = 1; i < consensus; ++i) 
	{
        award_list[i] -= i;
        list_end_award += i;
    }

    auto temp_consensus = consensus;
    auto diff_value = 10; //最后值差度(值越大相差越大)
    while (list_end_award > diff_value) 
	{
        if (list_end_award > diff_value && list_end_award < consensus) 
		{
            consensus = diff_value;
        }
        for (auto i = 1; i < consensus; ++i) 
		{ //XXX
            award_list[i] += 1; //XXX
        }
        if (list_end_award < consensus) 
		{
            list_end_award -= diff_value;
        } 
		else 
		{
            list_end_award -= consensus-1;
        }

    }

    award_list[temp_consensus] += list_end_award;
    sort(award_list.begin(), award_list.end());

    //去除负数情况
    while (award_list[0] <= 0) 
	{ //对称填负值
        for (auto i = 0; i < temp_consensus - 1; ++i) 
		{
            if (award_list[i] <= 0) 
			{
                if (award_list[i] == 0) 
				{
                    award_list[i] = 1;
                    award_list[temp_consensus-1-i] -= 1;
                } 
				else 
				{
                    award_list[i] = abs(award_list[i]) + 1;
                    award_list[temp_consensus-1-i] -= award_list[i] + (award_list[i] - 1);
                }
            } 
			else 
			{
                break;
            }
        }

        sort(award_list.begin(), award_list.end());
    }

    //最后一笔奖励不能等于上一笔 XXX
    while (award_list[temp_consensus-1] == award_list[temp_consensus-2]) 
	{
        award_list[temp_consensus-1] += 1;
        award_list[temp_consensus-2] -= 1;
        sort(award_list.begin(), award_list.end());
    }

    if (amount == 0) 
	{
        for (auto &v : award_list) 
		{
            v = 0;
        }
    }

    return 1;
}

bool ExitGuardian()
{
	std::string name = "ebpc_daemon";
	char cmd[128];
	memset(cmd, 0, sizeof(cmd));

	sprintf(cmd, "ps -ef | grep %s | grep -v grep | awk '{print $2}' | xargs kill -9 ",name.c_str());
	system(cmd);
	return true;
}


void HandleBuileBlockBroadcastMsg( const std::shared_ptr<BuileBlockBroadcastMsg>& msg, const MsgData& msgdata )
{
	// 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{
		ERRORLOG("HandleBuileBlockBroadcastMsg IsVersionCompatible");
		return ;
	}

	std::string serBlock = msg->blockraw();
	CBlock cblock;
	cblock.ParseFromString(serBlock);

	MagicSingleton<BlockPoll>::GetInstance()->Add(Block(cblock));
}

// Create: receive pending transaction from network and add to cache,  20210114   Liu
void HandleTxPendingBroadcastMsg(const std::shared_ptr<TxPendingBroadcastMsg>& msg, const MsgData& msgdata)
{
	// 判断版本是否兼容
	if (Util::IsVersionCompatible(msg->version()) != 0)
	{
		ERRORLOG("HandleTxPendingBroadcastMsg IsVersionCompatible");
		return ;
	}

	std::string transactionRaw = msg->txraw();
	CTransaction tx;
	tx.ParseFromString(transactionRaw);
	int result = MagicSingleton<TxVinCache>::GetInstance()->Add(tx, false);
	DEBUGLOG("Receive pending transaction broadcast message result:{} ", result);
}


int VerifyBuildBlock(const CBlock & cblock)
{
	// 检查签名节点是否有异常账号
	std::vector<std::string> addrList;
	if ( 0 != GetAbnormalAwardAddrList(addrList) )
	{
		ERRORLOG("GetAbnormalAwardAddrList failed!");
		return -1;
	}

	for (auto & tx : cblock.txs())
	{
		if (CheckTransactionType(tx) == kTransactionType_Award)
		{
			for (auto & txout : tx.vout())
			{
				if (addrList.end() != find(addrList.begin(), addrList.end(), txout.scriptpubkey()))
				{
					std::vector<std::string> txOwnerVec;
					SplitString(tx.txowner(), txOwnerVec, "_");

					if (txOwnerVec.end() == find(txOwnerVec.begin(), txOwnerVec.end(), txout.scriptpubkey()))
					{
						if (txout.value() != 0)
						{
							ERRORLOG("sign addr Abnormal !");
							return -2;
						}
					}
				}
			}
		}
	}

	return 0;
}

int BuildBlock(std::string &recvTxString, const std::shared_ptr<TxMsg>& SendTxMsg)
{
	CTransaction tx;
	tx.ParseFromString(recvTxString);

	if (! checkTransaction(tx))
	{
		ERRORLOG("BuildBlock checkTransaction");
		return -1;
	}
	CBlock cblock = CreateBlock(tx, SendTxMsg);
	if (cblock.hash().empty())
	{
		return -6;
	}

	std::string serBlock = cblock.SerializeAsString();

	if ( 0 != VerifyBuildBlock(cblock) ) 
	{
		ERRORLOG("VerifyBuildBlock failed ! ");
		return -2;
	}
	//验证合法性
	bool ret = VerifyBlockHeader(cblock);

	if(!ret)
	{
		ERRORLOG("BuildBlock VerifyBlockHeader fail!!!");
		return -3;
	}
	if(MagicSingleton<BlockPoll>::GetInstance()->CheckConflict(cblock))
	{
		ERRORLOG("BuildBlock BlockPoll have CheckConflict!!!");
		return -4;
	}

	if (MagicSingleton<TxVinCache>::GetInstance()->IsBroadcast(tx.hash()))
	{
		ERRORLOG("Block has already broadcas");
		return -5;
	}

	BuileBlockBroadcastMsg buileBlockBroadcastMsg;
	buileBlockBroadcastMsg.set_version(getVersion());
	buileBlockBroadcastMsg.set_blockraw(serBlock);

	net_broadcast_message<BuileBlockBroadcastMsg>(buileBlockBroadcastMsg, net_com::Priority::kPriority_High_1);

	MagicSingleton<TxVinCache>::GetInstance()->SetBroadcastFlag(tx.hash());
	// Add transaction broadcast time, 20210506   Liu
	MagicSingleton<TxVinCache>::GetInstance()->UpdateTransactionBroadcastTime(tx.hash());
	
	INFOLOG("BuildBlock BuileBlockBroadcastMsg");
	return 0;
}

int IsBlockExist(const std::string & blkHash)
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if (!txn)
	{
		ERRORLOG("TransactionInit error !");
		return -1;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	unsigned int blockHeight = 0;
	if (0 != pRocksDb->GetBlockHeightByBlockHash(txn, blkHash, blockHeight))
	{
		ERRORLOG("GetBlockHeightByBlockHash error !");
		return -2;
	}

	return 0;
}

int CalcTxTryCountDown(int needVerifyPreHashCount)
{
	if (needVerifyPreHashCount < g_MinNeedVerifyPreHashCount)
	{
		return 0;
	}
	else
	{
		return needVerifyPreHashCount - 4;
	}
}

int GetTxTryCountDwon(const TxMsg & txMsg)
{
	return txMsg.trycountdown();
}

int GetLocalDeviceOnlineTime(double_t & onlinetime)
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(GetLocalDeviceOnlineTime) TransactionInit failed !");
		return -1;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	int ret = 0;
	std::string ownPubKey = GetDefault58Addr();
	std::vector<string> pledgeUtxos;
	if (0 != pRocksDb->GetPledgeAddressUtxo(txn, ownPubKey, pledgeUtxos))
	{
		ret = 1;
	}

	uint64_t pledgeTime = time(NULL);
	uint64_t startTime = pledgeTime;
	for (auto & hash : pledgeUtxos)
	{
		std::string txRaw;
		if (0 != pRocksDb->GetTransactionByHash(txn, hash, txRaw))
		{
			ret = -2;
		}

		CTransaction utxoTx;
		utxoTx.ParseFromString(txRaw);

		for (auto & txout : utxoTx.vout())
		{
			if (txout.scriptpubkey() == VIRTUAL_ACCOUNT_PLEDGE)
			{
				if (txout.value() > (int64_t)g_TxNeedPledgeAmt && utxoTx.time() < pledgeTime)
				{
					pledgeTime = utxoTx.time();
				}
			}
		}
	}
	
	if (pledgeTime == startTime)
	{
		onlinetime = 1;
	}
	else
	{
		onlinetime = (time(NULL) - pledgeTime) / 3600 / 24;
		onlinetime = onlinetime > 1 ? onlinetime : 1;
	}

	return ret;
}

int SendTxMsg(const CTransaction & tx, const std::shared_ptr<TxMsg>& msg, uint32_t number)
{
	// 所有签过名的节点的id
	std::vector<std::string> signedIds;  
	for (auto & item : msg->signnodemsg())
	{
		signedIds.push_back( item.id() );
	}

	std::vector<std::string> sendid;
	int ret = FindSignNode(tx, number, signedIds, sendid);
	if( ret < 0 )
	{
		return -1;
	}

	for (auto id : sendid)
	{
		DEBUGLOG("net_send_message TxMsg to:{}", id);
		net_send_message<TxMsg>(id.c_str(), *msg, net_com::Priority::kPriority_High_1);
	}

	return 0;
}

int RetrySendTxMsg(const CTransaction & tx, const std::shared_ptr<TxMsg>& msg)
{
	int tryCountDown = msg->trycountdown();
	tryCountDown--;
	msg->set_trycountdown(tryCountDown);
	if (tryCountDown <= 0)
	{
		return -1;
	}
	else
	{
		// 继续尝试转发
		SendTxMsg(tx, msg, 1);
	}

	return 0;
}

int AddSignNodeMsg(const std::shared_ptr<TxMsg>& msg)
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		return -1;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	// 是否有足够质押节点
	bool isEnoughPledgeNode = false;
	uint32_t pledegeNodeCount = 0;
	std::vector<std::string> addressVec;
	pRocksDb->GetPledgeAddress(txn, addressVec);

	for (auto & addr : addressVec)
	{
		uint64_t pledgeamount = 0;
		SearchPledge(addr, pledgeamount);
		if (pledgeamount >= g_TxNeedPledgeAmt)
		{
			pledegeNodeCount++;
		}
		if (pledegeNodeCount > g_minPledgeNodeNum)
		{
			isEnoughPledgeNode = true;
			break;
		}
	}

	double_t onlinetime = 0.0;
	if (0 > GetLocalDeviceOnlineTime(onlinetime))
	{
		if (isEnoughPledgeNode)
		{
			return -2;
		}
	}

	uint64_t mineSignatureFee = 0;
	pRocksDb->GetDeviceSignatureFee( mineSignatureFee );
	if(mineSignatureFee <= 0)
	{
		return -3;
	}

	std::string default58Addr = GetDefault58Addr();

	uint64_t addrAwardTotal = 0;
	pRocksDb->GetAwardTotalByAddress(txn, default58Addr, addrAwardTotal);
	
	uint64_t signSum = 0;
	pRocksDb->GetSignNumByAddress(txn, default58Addr, signSum);

	SignNodeMsg * psignNodeMsg = msg->add_signnodemsg();
	psignNodeMsg->set_id(net_get_self_node_id());
	psignNodeMsg->set_signpubkey( default58Addr );
	psignNodeMsg->set_gasfee( std::to_string( mineSignatureFee ) );
	psignNodeMsg->set_onlinetime(onlinetime);
	psignNodeMsg->set_awardtotal(addrAwardTotal);
	psignNodeMsg->set_signsum(signSum);

	std::string ser = psignNodeMsg->SerializeAsString();
	std::string signatureMsg;
	std::string strPub;
	GetSignString(ser, signatureMsg, strPub);
	psignNodeMsg->set_signmsg(signatureMsg);

	return 0;
}

int CheckTxMsg( const std::shared_ptr<TxMsg>& msg )
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if (txn == NULL)
	{
		return -1;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	// 取交易体
	CTransaction tx;
	tx.ParseFromString(msg->tx());

	// 取交易发起方
	std::vector<std::string> vTxOwners = TxHelper::GetTxOwner(tx);

	// 取流转交易体中签名者
	std::vector<std::string> vMsgSigners;
	for (const auto & signer : msg->signnodemsg())
	{
		vMsgSigners.push_back(signer.signpubkey());
	}

	// 取交易体中签名者
	std::vector<std::string> vTxSigners;
	for (const auto & signInfo : tx.signprehash())
	{
		std::string addr = GetBase58Addr(signInfo.pub());
		vTxSigners.push_back(addr);
	}

	std::sort(vMsgSigners.begin(), vMsgSigners.end());
	std::sort(vTxSigners.begin(), vTxSigners.end());

	// 比对差异
	if (vMsgSigners != vTxSigners)
	{
		return -2;
	}

	// 取交易类型
	bool bIsPledgeTx = false;
	auto extra = nlohmann::json::parse(tx.extra());
	std::string txType = extra["TransactionType"].get<std::string>();
	if ( txType == TXTYPE_PLEDGE )
	{
		bIsPledgeTx = true;
	}

	// 取全网质押账号
	std::vector<string> pledgeAddrs;
	pRocksDb->GetPledgeAddress(txn, pledgeAddrs);

	// 判断是否为初始账号交易
	bool bIsInitAccount = false;
	if (vTxOwners.end() != find(vTxOwners.begin(), vTxOwners.end(), g_InitAccount))
	{
		bIsInitAccount = true;
	}

	// 判断签名节点是否需要质押
	if ( (bIsPledgeTx || bIsInitAccount) && pledgeAddrs.size() < g_minPledgeNodeNum )
	{
		return 0;
	}

	// 判断签名节点质押金额
	for (auto & addr : vTxSigners)
	{
		// 发起方不进行质押判断
		if (vTxOwners.end() != std::find(vTxOwners.begin(), vTxOwners.end(), addr))
		{
			continue;
		}

		uint64_t amount = 0;
		SearchPledge(addr, amount);
		if (amount < g_TxNeedPledgeAmt)
		{
			return -3;
		}
	}
	return 0;
}

void HandleTx( const std::shared_ptr<TxMsg>& msg, const MsgData& msgdata)
{
	std::string tx_hash;
	DoHandleTx( msg, tx_hash);
}

int DoHandleTx( const std::shared_ptr<TxMsg>& msg, std::string & tx_hash )
{
	// 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{
		return -1;
	}
	
	// 判断高度是否符合
	if(!checkTop(msg->top()))
	{
		return -2;
	}

	// 检查本节点是否存在该交易的父块
	if (IsBlockExist(msg->prevblkhash()))
	{
		return -3;
	}

	INFOLOG("Recv TX ...");

	//TX的头部带有签名过的网络节点的id，格式为 num [nodeid,nodeid,...] tx // 可删除
	CTransaction tx;
	tx.ParseFromString(msg->tx());

	// 此次交易的共识数
	auto extra = nlohmann::json::parse(tx.extra());
    int needVerifyPreHashCount = extra["NeedVerifyPreHashCount"].get<int>();
	if (needVerifyPreHashCount < g_MinNeedVerifyPreHashCount)
	{
		return -4;
	}

	CalcTransactionHash(tx);

	if (! checkTransaction(tx))
	{
		return -5;
	}

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		return -6;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	// 所有签过名的节点的id
	std::vector<std::string> signedIds;
	for (auto & item : msg->signnodemsg())
	{
		signedIds.push_back( item.id() );
		if (item.onlinetime() <= 0)
		{
			return -7;
		}
	}

	if (0 != CheckTxMsg(msg))
	{
		return -8;
	}

	//验证别人的签名
	int verifyPreHashCount = 0;
	std::string txBlockHash;
	std::string blockPrevHash;
	bool rc = VerifyTransactionSign(tx, verifyPreHashCount, txBlockHash, msg->txencodehash());
	if(!rc)
	{
		if(tx.signprehash_size() == 0)
		{
			return -9;
		}
		else
		{
			ERRORLOG("tx.signprehash_size() != 0");
			return (0 != RetrySendTxMsg(tx, msg) ? -9 : 0);
		}
	}

	INFOLOG("verifyPreHashCount: {}", verifyPreHashCount);

	if ( verifyPreHashCount < needVerifyPreHashCount && ContainSelfSign(tx))
	{
		ERRORLOG(" verifyPreHashCount < needVerifyPreHashCount && ContainSelfSign(tx)");
		return (0 != RetrySendTxMsg(tx, msg) ? -10 : 0);
	}

	// 判断是否为质押交易
	bool isPledgeTx = false;
	std::string txType = extra["TransactionType"].get<std::string>();
	if (txType == TXTYPE_PLEDGE)
	{
		isPledgeTx = true;
	}

	// 判断是否为初始账号发起的交易
	bool isInitAccountTx = false;
	for (int i = 0; i < tx.vout_size(); ++i)
	{
		CTxout txout = tx.vout(i);
		if (txout.scriptpubkey() == g_InitAccount)
		{
			isInitAccountTx = true;
		}
	}

	// 账号未质押不允许签名转账交易, 但允许签名质押交易
	// verifyPreHashCount == 0 时为自己发起交易允许签名，verifyPreHashCount == needVerifyPreHashCount 时签名已经足够 开始建块
	if (!isPledgeTx && !isInitAccountTx && (verifyPreHashCount != 0 && verifyPreHashCount != needVerifyPreHashCount) )
	{
		std::string defauleAddr = GetDefault58Addr();

		uint64_t amount = 0;
		SearchPledge(defauleAddr, amount);
		if (amount < g_TxNeedPledgeAmt && defauleAddr != g_InitAccount)
		{
			ERRORLOG("amount < g_TxNeedPledgeAmt && defauleAddr != g_InitAccount");
			return (0 != RetrySendTxMsg(tx, msg) ? -11 : 0);
		}
	}

	// 交易接收方禁止签名
	std::string default58Addr = GetDefault58Addr();
	for(int i = 0; i < tx.vout_size(); i++)
	{
		CTxout txout = tx.vout(i);
		if(default58Addr == txout.scriptpubkey())
		{
			auto txOwners = TxHelper::GetTxOwner(tx);
			if (txOwners.end() == std::find(txOwners.begin(), txOwners.end(), default58Addr))
			{
				ERRORLOG("txOwners.end() == std::find(txOwners.begin(), txOwners.end(), default58Addr)");
				return (0 != RetrySendTxMsg(tx, msg) ? -12 : 0);
			}
		}
	}

	// 自身开始签名
	if ( verifyPreHashCount < needVerifyPreHashCount)
	{
		tx_hash = tx.hash();
		//自己来签名
		std::string strSignature;
		std::string strPub;
		GetSignString(txBlockHash, strSignature, strPub);

		DEBUGLOG("GetDefault58Addr():{} add Sign ...",  GetDefault58Addr());

		CSignPreHash * signPreHash = tx.add_signprehash();
		signPreHash->set_sign(strSignature);
		signPreHash->set_pub(strPub);
		verifyPreHashCount++;
	}
	
	uint64_t mineSignatureFee = 0;
	pRocksDb->GetDeviceSignatureFee( mineSignatureFee );
	if(mineSignatureFee <= 0)
	{
		if (tx.signprehash_size() == 1)
		{
			// 发起方必须设置矿费
			return -13;
		}
		else
		{
			// 交易流转节点可重试发送
			return (0 != RetrySendTxMsg(tx, msg) ? -13 : 0);
		}
	}

	std::string ownID = net_get_self_node_id();
	int txOwnerPayGasFee = extra["SignFee"].get<int>();
	if (ownID != tx.ip())
	{
		// 交易发起方所支付的手续费低于本节点设定的签名费时不予签名
		if(verifyPreHashCount != 0 && ((uint64_t)txOwnerPayGasFee) < mineSignatureFee )
		{
			
			ERRORLOG("txOwners.end() == std::find(txOwners.begin(), txOwners.end(), default58Addr)");
			return (0 != RetrySendTxMsg(tx, msg) ? -14 : 0);
		}
	}

	if((uint64_t)txOwnerPayGasFee < g_minSignFee || (uint64_t)txOwnerPayGasFee > g_maxSignFee)
	{
		return -15;
	}
 
	std::string serTx = tx.SerializeAsString();
	msg->set_tx(serTx);

	if (verifyPreHashCount < needVerifyPreHashCount)
	{
		// 签名数不足时

		// 添加交易流转的签名信息		
		if (0 != AddSignNodeMsg(msg))
		{
			return -16;
		}

		// todo 有bug，临时注掉
		// if (CheckAllNodeChainHeightInReasonableRange() != 0)
		// {
		// 	ERRORLOG("Check chain height of node failed");
		// 	return -22;
		// }
		
		//只有一个签名,签名是自己,ip相等,添加到Cache中, 20201214
		if (ownID == tx.ip() && tx.signprehash_size() == 1)
		{
			char buf[2048] = {0};
			size_t buf_len = sizeof(buf);
			string pub = tx.signprehash(0).pub();
			GetBase58Addr(buf, &buf_len, 0x00, pub.c_str(), pub.size());
			std::string strBuf(buf, strlen(buf));

			std::string default58Addr = GetDefault58Addr();
			if (strBuf == default58Addr)
			{
				int result = MagicSingleton<TxVinCache>::GetInstance()->Add(tx);
				DEBUGLOG("Transaction add to Cach ({}) ({})", result, TxVinCache::TxToString(tx));
			}
		}

		int nodeSize = needVerifyPreHashCount * 1;
		if(verifyPreHashCount > 1)   
		{
			// 除自己本身签名外，其他节点签名的时候转发节点数为1
			nodeSize = 1;
		}

		if (0 != SendTxMsg(tx, msg, nodeSize))
		{
			return -17;
		}
		
		DEBUGLOG("TX begin broadcast");
	}
	else
	{
		// 签名数达到共识数
		std::string ip = net_get_self_node_id();

		if (ip != tx.ip())
		{
			// 如果是全网节点质押数
			
			// 添加交易流转的签名信息		
			if (0 != AddSignNodeMsg(msg))
			{
				return -18;
			}
			net_send_message<TxMsg>(tx.ip(), *msg, net_com::Priority::kPriority_High_1);
			DEBUGLOG("TX Send to ip[{}] to Create Block ...", tx.ip().c_str());
		}
		else
		{
			// 返回到发起节点
			std::string blockHash;
			pRocksDb->GetBlockHashByTransactionHash(txn, tx.hash(), blockHash);
			
			if(blockHash.length())
			{
				// 查询到说明已加块
				return -19;
			}

			if(msg->signnodemsg_size() != needVerifyPreHashCount)
			{
				return -20;
			}

			if( 0 != BuildBlock( serTx, msg) )
			{
				ERRORLOG("HandleTx BuildBlock fail");
				return -21;
			}
		}
	}
	return 0;
}

std::map<int32_t, std::string> GetPreTxRawCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"),
												make_pair(-2, "数据库打开错误"),
												make_pair(-2, "获取主链信息失败"),
												};
	return errInfo;
}

void HandlePreTxRaw( const std::shared_ptr<TxMsgReq>& msg, const MsgData& msgdata )
{
	TxMsgAck txMsgAck;

	auto errInfo = GetPreTxRawCode();

	// 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -1);
		return ;
	}

	// 将交易信息体，公钥，签名信息反base64
	unsigned char serTxCstr[msg->sertx().size()] = {0};
	unsigned long serTxCstrLen = base64_decode((unsigned char *)msg->sertx().data(), msg->sertx().size(), serTxCstr);
	std::string serTxStr((char *)serTxCstr, serTxCstrLen);

	CTransaction tx;
	tx.ParseFromString(serTxStr);

	unsigned char strsignatureCstr[msg->strsignature().size()] = {0};
	unsigned long strsignatureCstrLen = base64_decode((unsigned char *)msg->strsignature().data(), msg->strsignature().size(), strsignatureCstr);

	unsigned char strpubCstr[msg->strsignature().size()] = {0};
	unsigned long strpubCstrLen = base64_decode((unsigned char *)msg->strpub().data(), msg->strpub().size(), strpubCstr);

	for (int i = 0; i < tx.vin_size(); i++)
	{
		CTxin * txin = tx.mutable_vin(i);
		txin->mutable_scriptsig()->set_sign( std::string( (char *)strsignatureCstr, strsignatureCstrLen ) );
		txin->mutable_scriptsig()->set_pub( std::string( (char *)strpubCstr, strpubCstrLen ) );
	}

	std::string serTx = tx.SerializeAsString();

	auto extra = nlohmann::json::parse(tx.extra());
	int needVerifyPreHashCount = extra["NeedVerifyPreHashCount"].get<int>();

	TxMsg phoneToTxMsg;
	phoneToTxMsg.set_version(getVersion());
	phoneToTxMsg.set_tx(serTx);
	phoneToTxMsg.set_txencodehash(msg->txencodehash());

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -2);
		return;
	}

	bool bRollback = true;
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, bRollback);
	};

	std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
    	ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -3);
        return;
    }
    phoneToTxMsg.set_prevblkhash(blockHash);
	phoneToTxMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));

	unsigned int top = 0;
	pRocksDb->GetBlockTop(txn, top);	
	phoneToTxMsg.set_top(top);

	auto txmsg = make_shared<TxMsg>(phoneToTxMsg);
	std::string txHash;
	int ret = DoHandleTx(txmsg, txHash);
	txMsgAck.set_txhash(txHash);
	if (ret != 0)
	{
		ret -= 100;
	}
	DEBUGLOG("DoHandleTx ret:{} ", ret);
	ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, ret);
}

/* ====================================================================================  
 # 手机端交易流程：
 # 1，手机端发送CreateTxMsgReq请求到PC端，PC端调用HandleCreateTxInfoReq接口处理手机端请求；
 # 2，PC端在HandleCreateTxInfoReq中通过手机端发送的交易关键信息，打包成交易信息体，并将交易信息体进行base64之后，
 #    通过CreateTxMsgAck协议回传给手机端，CreateTxMsgAck协议中的txHash字段，是由交易体base64之后，再进
 #    行sha256，得到的hash值
 # 3，手机端接收到CreateTxMsgAck后，将自己计算的hash与PC传过来的txHash进行比较，不一致说明数据有误；一致，则调
 #    调用interface_NetMessageReqTxRaw对hash值进行签名。
 # 4，手机端回传TxMsgReq到PC端，PC端通过HandlePreTxRaw接口处理接收到的手机端的交易
 ==================================================================================== */

 std::map<int32_t, std::string> GetCreateTxInfoReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"),
												make_pair(-2, "参数错误"),
												make_pair(-3, "未找到相关utxo"),
												};
	return errInfo;
}
// 手机端交易处理
void HandleCreateTxInfoReq( const std::shared_ptr<CreateTxMsgReq>& msg, const MsgData& msgdata )
{
	CreateTxMsgAck createTxMsgAck;
	auto errInfo = GetCreateTxInfoReqCode();

	// 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{
		ReturnAckCode<CreateTxMsgAck>(msgdata, errInfo, createTxMsgAck, -1);		
		return ;
	}

	// 通过手机端发送的数据创建交易体
	std::string txData;
	int ret = CreateTransactionFromRocksDb(msg, txData);
	if( 0 != ret )
	{
		std::string sendMessage;
		int code = -2;
		if(ret == -1)
		{
			sendMessage = "parameter error!";
		}
		else
		{
			code = -3;
			sendMessage = "UTXO not found!";
		}
		
		ReturnAckCode<CreateTxMsgAck>(msgdata, errInfo, createTxMsgAck, code);
		return ;
	}

	// 将交易体base64，方便传输，txHash用于手机端验证传输的数据是否正确
	size_t encodeLen = txData.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)txData.data(), txData.size(), encode);

	createTxMsgAck.set_txdata( (char *)encode, codeLen );
	std::string encodeStr((char *)encode, codeLen);
	std::string txEncodeHash = getsha256hash(encodeStr);
	createTxMsgAck.set_txencodehash(txEncodeHash);

	ReturnAckCode<CreateTxMsgAck>(msgdata, errInfo, createTxMsgAck, 0);
}

void HandleGetMacReq(const std::shared_ptr<GetMacReq>& getMacReq, const MsgData& from)
{	
	std::vector<string> outmac;
	get_mac_info(outmac);
	
	std::string macstr;
	for(auto &i:outmac)
	{
		macstr += i;
	}
	string md5 = getMD5hash(macstr.c_str());
	GetMacAck getMacAck;
	getMacAck.set_mac(md5);
	DEBUGLOG("getMD5hash:{}", md5);

	net_send_message(from, getMacAck);
}

int get_mac_info(vector<string> &vec)
{	 
	int fd;
    int interfaceNum = 0;
    struct ifreq buf[16] = {0};
    struct ifconf ifc;
    char mac[16] = {0};

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        ERRORLOG("socket ret:{}", fd);
        close(fd);
        return -1;
    }
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t)buf;
    if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        interfaceNum = ifc.ifc_len / sizeof(struct ifreq);
        while (interfaceNum-- > 0)
        {
            if(string(buf[interfaceNum].ifr_name) == "lo")
            {
                continue;
            }
            if (!ioctl(fd, SIOCGIFHWADDR, (char *)(&buf[interfaceNum])))
            {
                memset(mac, 0, sizeof(mac));
                snprintf(mac, sizeof(mac), "%02x%02x%02x%02x%02x%02x",
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[0],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[1],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[2],

                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[3],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[4],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[5]);
                // allmac[i++] = mac;
                std::string s = mac;
                vec.push_back(s);
            }
            else
            {
                ERRORLOG("ioctl: {}", strerror(errno));
                close(fd);
                return -1;
            }
        }
    }
    else
    {
        ERRORLOG("ioctl:{}", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int SearchPledge(const std::string &address, uint64_t &pledgeamount, std::string pledgeType)
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, false);
	};
	
	std::vector<string> utxos;
	int db_status = pRocksDb->GetPledgeAddressUtxo(txn, address, utxos);
	if (db_status != 0) 
	{
		ERRORLOG("GetPledgeAddressUtxo fail db_status:{}", db_status);
		return -1;
	}
	uint64_t total = 0;
	for (auto &item : utxos) 
    {
	 	std::string strTxRaw;
		if (pRocksDb->GetTransactionByHash(txn, item, strTxRaw) != 0)
		{
			continue;
		}
		CTransaction utxoTx;
		utxoTx.ParseFromString(strTxRaw);

		nlohmann::json extra = nlohmann::json::parse(utxoTx.extra());
		nlohmann::json txInfo = extra["TransactionInfo"].get<nlohmann::json>();
		std::string txPledgeType = txInfo["PledgeType"].get<std::string>();
		if (txPledgeType != pledgeType)
		{
			continue;
		}

		for (int i = 0; i < utxoTx.vout_size(); i++)
		{
			CTxout txout = utxoTx.vout(i);
			if (txout.scriptpubkey() == VIRTUAL_ACCOUNT_PLEDGE)
			{
				total += txout.value();
			}
		}
    }
	pledgeamount = total;
	return 0;
}

int GetAbnormalAwardAddrList(std::vector<std::string> & addrList)
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if (txn == NULL)
	{
		ERRORLOG("(GetAbnormalAwardAddrList) TransactionInit failed !");
		return -1;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	const uint64_t heightRange = 1000;  // 检查异常的高度范围
	std::map<std::string, uint64_t> addrAwards;  // 存放账号和前500高度总奖励
	std::map<std::string, uint64_t> addrSignNum;  // 存放账号和前500高度总签名数

	unsigned int top = 0;
	if ( 0 != pRocksDb->GetBlockTop(txn, top) )
	{
		ERRORLOG("(GetAbnormalAwardAddrList) GetBlockTop failed! ");
		return -2;
	}

	uint64_t minHeight = top > heightRange ? (int)top - heightRange : 0;  // 检查异常的最低高度

	for ( ; top != minHeight; --top)
	{
		std::vector<std::string> blockHashs;
		if ( 0 != pRocksDb->GetBlockHashsByBlockHeight(txn, top, blockHashs) )
		{
			ERRORLOG("(GetAbnormalAwardAddrList) GetBlockHashsByBlockHeight failed! ");
			return -3;
		}

		for (auto & hash : blockHashs)
		{
			std::string blockStr;
			if (0 != pRocksDb->GetBlockByBlockHash(txn, hash, blockStr))
			{
				ERRORLOG("(GetAbnormalAwardAddrList) GetBlockByBlockHash failed! ");
				return -4;
			}

			CBlock block;
			block.ParseFromString(blockStr);

			for (auto & tx : block.txs())
			{
				if (CheckTransactionType(tx) == kTransactionType_Award)
				{
					for (auto & txout : tx.vout())
					{
						if (txout.value() == 0)
						{
							continue;
						}

						// 总奖励
						auto iter = addrAwards.find(txout.scriptpubkey());
						if (addrAwards.end() != iter)
						{
							addrAwards[txout.scriptpubkey()] = iter->second + txout.value();
						}
						else
						{
							addrAwards[txout.scriptpubkey()] = txout.value();
						}

						// 总签名次数
						auto signNumIter = addrSignNum.find(txout.scriptpubkey());
						if (addrSignNum.end() != signNumIter)
						{
							addrSignNum[txout.scriptpubkey()] = (++signNumIter->second);
						}
						else
						{
							addrSignNum[txout.scriptpubkey()] = 1;
						}
						
					}
				}
			}
		}
	}

	if (addrAwards.size() == 0 || addrSignNum.size() == 0)
	{
		return 0;
	}

	std::vector<uint64_t> awards;  // 存放所有奖励值
	std::vector<uint64_t> vecSignNum;  // 存放所有奖励值
	for (auto & addrAward : addrAwards)
	{
		awards.push_back(addrAward.second);
	}

	for(auto & signNum : addrSignNum)
	{
		vecSignNum.push_back(signNum.second);
	}

	std::sort(awards.begin(), awards.end());
	std::sort(vecSignNum.begin(), vecSignNum.end());

	uint64_t awardQuarterNum = awards.size() * 0.25;
	uint64_t awardThreeQuarterNum = awards.size() * 0.75;
	
	uint64_t signNumQuarterNum = vecSignNum.size() * 0.25;
	uint64_t signNumThreeQuarterNum = vecSignNum.size() * 0.75;

	if (awardQuarterNum == awardThreeQuarterNum || signNumQuarterNum == signNumThreeQuarterNum)
	{
		return 0;
	}

	uint64_t awardQuarterValue = awards[awardQuarterNum];
	uint64_t awardThreeQuarterValue = awards[awardThreeQuarterNum];

	uint64_t signNumQuarterValue = vecSignNum[signNumQuarterNum];
	uint64_t signNumThreeQuarterValue = vecSignNum[signNumThreeQuarterNum];

	uint64_t awardDiffValue = awardThreeQuarterValue - awardQuarterValue;
	uint64_t awardUpperLimitValue = awardThreeQuarterValue + (awardDiffValue * 1.5);

	uint64_t signNumDiffValue = signNumThreeQuarterValue - signNumQuarterValue;
	uint64_t signNumUpperLimitValue = signNumThreeQuarterValue + (signNumDiffValue * 1.5);

	std::vector<std::string> awardList;
	std::vector<std::string> signNumList;
	for (auto & addrAward : addrAwards)
	{
		if (addrAward.second > awardUpperLimitValue)
		{
			awardList.push_back(addrAward.first);
		}
	}

	for (auto & addrSign : addrSignNum)
	{
		if (addrSign.second > signNumUpperLimitValue)
		{
			signNumList.push_back(addrSign.first);
		}
	}

	set_union(awardList.begin(), awardList.end(), signNumList.begin(), signNumList.end(), std::back_inserter(addrList));

	return 0;
}

int FindSignNode(const CTransaction & tx, const int nodeNumber, const std::vector<std::string> & signedNodes, std::vector<std::string> & nextNodes)
{
	// 参数判断
	if(nodeNumber <= 0)
	{
		return -1;
	}

	nlohmann::json txExtra = nlohmann::json::parse(tx.extra());
	uint64_t minerFee = txExtra["SignFee"].get<int>();

	bool isPledge = false;
	std::string txType = txExtra["TransactionType"].get<std::string>();
	if (txType == TXTYPE_PLEDGE)
	{
		isPledge = true;
	}

	bool isInitAccount = false;
	std::vector<std::string> vTxowners = TxHelper::GetTxOwner(tx);
	if (vTxowners.size() == 1 && vTxowners.end() != find(vTxowners.begin(), vTxowners.end(), g_InitAccount) )
	{
		isInitAccount = true;
	}

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		return -2;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, false);
	};

	const Node & selfNode = Singleton<PeerNode>::get_instance()->get_self_node();
	std::vector<Node> nodelist;
	if (selfNode.is_public_node)
	{
		nodelist = Singleton<PeerNode>::get_instance()->get_nodelist();
	}
	else
	{
		nodelist = Singleton<NodeCache>::get_instance()->get_nodelist();
	}
	
	// 当前数据块高度为0时，GetPledgeAddress会返回错误，故不做返回判断
	std::vector<string> addresses; // 已质押地址
	std::vector<string> pledgeAddrs; // 待选的已质押地址
	// pRocksDb->GetPledgeAddress(txn, addresses);
	pRocksDb->GetPledgeAddress(txn, pledgeAddrs);

	// 去除base58重复的节点
	std::map<std::string, std::string> tmpBase58Ids; // 临时去重
	std::vector<std::string> vRepeatedIds; // 重复的地址
	
	for (auto & node : nodelist)
	{
		// 查询列表中已质押地址
		// std::string addr = node.base58address;
		// auto iter = find(addresses.begin(), addresses.end(), addr);
		// if (iter != addresses.end())
		// {
		// 	pledgeAddrs.push_back(addr);
		// }

		// 查询重复base58地址
		auto ret = tmpBase58Ids.insert(make_pair(node.base58address, node.id));
		if (!ret.second)
		{
			vRepeatedIds.push_back(node.id);
		}
	}
	
	for (auto & id : vRepeatedIds)
	{
		auto iter = std::find_if(nodelist.begin(), nodelist.end(), [id](auto & node){
			return id == node.id;
		});
		if (iter != nodelist.end())
		{
			nodelist.erase(iter);
		}
	}

	std::string ownerID = net_get_self_node_id(); // 自己的节点

	// 取出交易双方
	std::vector<std::string> txAddrs;
	for(int i = 0; i < tx.vout_size(); ++i)
	{
		CTxout txout = tx.vout(i);
		txAddrs.push_back(txout.scriptpubkey());
	}

	// 获取异常账户的节点
	std::vector<std::string> abnormalAddrList;
	if ( 0 != GetAbnormalAwardAddrList(abnormalAddrList) )
	{
		ERRORLOG("(FindSignNode) GetAbnormalAwardAddrList failed! ");
		return -3;
	}
	
	for (auto iter = nodelist.begin(); iter != nodelist.end(); )
	{
		// 删除自身节点
		if (iter->id == ownerID)
		{
			iter = nodelist.erase(iter);
			continue;
		}

		// 删除交易双方节点
		if (txAddrs.end() != find(txAddrs.begin(), txAddrs.end(), iter->base58address))
		{
			iter = nodelist.erase(iter);
			continue;
		}

		// 去除奖励值异常账号
		
		if (abnormalAddrList.end() != find(abnormalAddrList.begin(), abnormalAddrList.end(), iter->base58address))
		{
			iter = nodelist.erase(iter);
			continue;
		}

		if (iter->chain_height + REASONABLE_HEIGHT_RANGE < selfNode.chain_height || 
			selfNode.chain_height + REASONABLE_HEIGHT_RANGE < iter->chain_height)
		{
			iter = nodelist.erase(iter);
			continue;
		}

		++iter;
	}
	
	std::vector<std::pair<std::string, uint64_t>> vecIdsInfos;
	for (auto & node : nodelist)
	{
		vecIdsInfos.push_back(std::make_pair(node.id, node.fee));
	}

	// 随机取节点
	random_device rd;
	while (nextNodes.size() != (uint64_t)nodeNumber && vecIdsInfos.size() != 0)
	{
		default_random_engine rng {rd()};
		uniform_int_distribution<int> dist {0, (int)vecIdsInfos.size() - 1};
		int randNum = dist(rng);

		if (vecIdsInfos[randNum].second <= minerFee)
		{
			std::string id = vecIdsInfos[randNum].first;
			
			auto iter = std::find_if(nodelist.begin(), nodelist.end(), [id](auto & node){
				return id == node.id;
			});

			if (nodelist.end() != iter)
			{
				if ( (isPledge || isInitAccount) && pledgeAddrs.size() < g_minPledgeNodeNum )
				{
					
					nextNodes.push_back(iter->id);
				}
				else
				{
					uint64_t pledgeAmount = 0;
					if ( 0 != SearchPledge(iter->base58address, pledgeAmount) )
					{
						vecIdsInfos.erase(vecIdsInfos.begin() + randNum);
						continue;
					}

					if (pledgeAmount >= g_TxNeedPledgeAmt)
					{
						nextNodes.push_back(iter->id);
					}
				}
			}
		}
		vecIdsInfos.erase(vecIdsInfos.begin() + randNum);
	}

	// 过滤已签名的
	for(auto signedId : signedNodes)
	{
		auto iter = std::find(nextNodes.begin(), nextNodes.end(), signedId);
		if (iter != nextNodes.end())
		{
			nextNodes.erase(iter);
		}
	}

	// 筛选随机节点
	std::vector<std::string> sendid;
	if (nextNodes.size() <= (uint32_t)nodeNumber)
	{
		for (auto & nodeid  : nextNodes)
		{
			sendid.push_back(nodeid);
		}
	}
	else
	{
		std::set<int> rSet;
		srand(time(NULL));
		int num = std::min((int)nextNodes.size(), nodeNumber);
		for(int i = 0; i < num; i++)
		{
			int j = rand() % nextNodes.size();
			rSet.insert(j);		
		}

		for (auto i : rSet)
		{
			sendid.push_back(nextNodes[i]);
		}
	}

	nextNodes = sendid;

	return 0;
}

void GetOnLineTime()
{
	static time_t startTime = time(NULL);
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if(!txn) 
	{
		ERRORLOG(" TransactionInit failed !");
		return ;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	{
		// patch
		double minertime = 0.0;
		if (0 != pRocksDb->GetDeviceOnLineTime(minertime))
		{
			if ( 0 != pRocksDb->SetDeviceOnlineTime(0.00001157) )
			{
				ERRORLOG("(GetOnLineTime) SetDeviceOnlineTime failed!");
				return;
			}
		}

		if (minertime > 365.0)
		{
			if ( 0 != pRocksDb->SetDeviceOnlineTime(0.00001157) )
			{
				ERRORLOG("(GetOnLineTime) SetDeviceOnlineTime failed!");
				return;
			}
		}
	}

	// 从有交易开始记录在线时长
	std::vector<std::string> vTxHashs;
	std::string addr = g_AccountInfo.DefaultKeyBs58Addr;
	int db_get_status = pRocksDb->GetAllTransactionByAddreess(txn, addr, vTxHashs); 	
	if (db_get_status != 0) 
	{
		ERRORLOG(" GetAllTransactionByAddreess failed db_get_status:{}!", db_get_status);
	}

	std::vector<Node> vnode = net_get_public_node();
	if(vTxHashs.size() >= 1 && vnode.size() >= 1 )
	{
		double onLineTime = 0.0;
		if ( 0 != pRocksDb->GetDeviceOnLineTime(onLineTime) )
		{
			if ( 0 != pRocksDb->SetDeviceOnlineTime(0.00001157) )
			{
				ERRORLOG("(GetOnLineTime) SetDeviceOnlineTime failed!");
				return;
			}
			return ;
		}

		time_t endTime = time(NULL);
		time_t dur = difftime(endTime, startTime);
		double durDay = (double)dur / (1*60*60*24);
		
		double minertime = 0.0;
		if (0 != pRocksDb->GetDeviceOnLineTime(minertime))
		{
			ERRORLOG("(GetOnLineTime) GetDeviceOnLineTime failed!");
			return ;
		}

		double accumatetime = durDay + minertime; 
		if ( 0 != pRocksDb->SetDeviceOnlineTime(accumatetime) )
		{
			ERRORLOG("(GetOnLineTime) SetDeviceOnlineTime failed!");
			return ;
		}
		
		startTime = endTime;
	}
	else
	{
		startTime = time(NULL);
	}
	
	if ( 0 != pRocksDb->TransactionCommit(txn) )
	{
		ERRORLOG("(GetOnLineTime) TransactionCommit failed!");
		return ;
	}
}

int PrintOnLineTime()
{
	double  onlinetime;
	auto 	pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	int 	db_status = pRocksDb->GetDeviceOnLineTime(onlinetime);
	int  day = 0,hour = 0,minute = 0,second = 0;

    double totalsecond = onlinetime *86400;

	cout<<"totalsecond="<<totalsecond<<endl;

	day = totalsecond/86400;
	cout<<"day="<< day <<endl;

	hour = (totalsecond - (day *86400))/3600;
	cout<<"hour="<< hour <<endl;

	minute = (totalsecond - (day *86400) - (hour *3600))/60;
	cout<<"minute="<< minute <<endl;

	second = (totalsecond - (day *86400) - (hour *3600) - (minute *60));
	cout<<"second="<< second <<endl;

	cout<<"day:"<<day<<"hour:"<<hour<<"minute:"<<minute <<"second:"<< second<<endl;

	if(db_status != 0)
	{
		ERRORLOG("Get the device time  failed db_status:{}", db_status);
		return -1;
	}    
	return 0;        
}

int TestSetOnLineTime()
{
	cout<<"先查看在线时长然后设置设备在线时长"<<endl;
	PrintOnLineTime();
	std::cout <<"请输入设备的在线时长"<<std::endl;
	
	static double day  = 0.0,hour = 0.0,minute = 0.0,second = 0.0,totalsecond = 0.0,accumlateday=0.0;
	double inday  = 0.0,inhour = 0.0,inminute = 0.0,insecond = 0.0,intotalsecond = 0.0,inaccumlateday=0.0;
	cout<<"请输入设备在线天数"<<endl;
	std::cin >> inday;
	cout<<"请输入设备在线小时数"<<endl;
	std::cin >> inhour;
	cout<<"请输入设备在线分钟数"<<endl;
	std::cin >> inminute;
	cout<<"请输入设备在线秒数"<<endl;
	std::cin >> insecond;
	
	intotalsecond = inday *86400 + inhour *3600 + inminute*60 +insecond;
	inaccumlateday = intotalsecond/86400;
	
	cout<<"input day="<< inday<<endl;
	cout<<"input hour="<< inhour <<endl;
	cout<<"input minute="<< inminute <<endl;
	cout<<"input second="<< insecond <<endl;
	cout<< "input accumlateday= "<< inaccumlateday <<endl;
	cout<<"input totalsecond = "<<intotalsecond <<endl;
	day  += inday; 
	hour += inhour;
	minute += inminute;
	second += insecond;
	totalsecond = day *86400 + hour *3600 + minute*60 +second;
	accumlateday = totalsecond/86400;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	// std::string time;
	// std::cin >> time;
	// std::stringstream ssAmount(time);
	// double day;
	// ssAmount >> day;
  	int db_status = pRocksDb->SetDeviceOnlineTime(accumlateday);
	if(db_status == 0)
	{
		INFOLOG("set the data success");
		return 0;
	}
	return -1;
}


/** 手机端连接矿机发起交易前验证矿机密码(测试连接是否成功) */
void HandleVerifyDevicePassword( const std::shared_ptr<VerifyDevicePasswordReq>& msg, const MsgData& msgdata )
{	
	VerifyDevicePasswordAck verifyDevicePasswordAck;
	verifyDevicePasswordAck.set_version(getVersion());

	// 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{
		verifyDevicePasswordAck.set_code(-1);
		verifyDevicePasswordAck.set_message("version error!");
		net_send_message<VerifyDevicePasswordAck>(msgdata, verifyDevicePasswordAck);
		ERRORLOG("HandleBuileBlockBroadcastMsg IsVersionCompatible");
		return ;
	}

	string  minerpasswd = Singleton<DevicePwd>::get_instance()->GetDevPassword();
	std::string passwordStr = generateDeviceHashPassword(msg->password());
	std::string password = msg->password();
    std::string hashOriPass = generateDeviceHashPassword(password);
    std::string targetPassword = Singleton<DevicePwd>::get_instance()->GetDevPassword();
    auto pCPwdAttackChecker = MagicSingleton<CPwdAttackChecker>::GetInstance(); 
   
    uint32_t minutescount ;
    bool retval = pCPwdAttackChecker->IsOk(minutescount);
    if(retval == false)
    {
        std::string minutescountStr = std::to_string(minutescount);
        verifyDevicePasswordAck.set_code(-31);
        verifyDevicePasswordAck.set_message(minutescountStr);
		
        ERRORLOG("有连续3次错误，{}秒之后才可以输入", minutescount);
		net_send_message<VerifyDevicePasswordAck>(msgdata, verifyDevicePasswordAck);
        return;
    }

    if(hashOriPass.compare(targetPassword))
    {
        DEBUGLOG("输入密码错误开始记录次数");
       if(pCPwdAttackChecker->Wrong())
       {
            ERRORLOG("密码输入错误");
            verifyDevicePasswordAck.set_code(-2);
            verifyDevicePasswordAck.set_message("密码输入错误");
			net_send_message<VerifyDevicePasswordAck>(msgdata, verifyDevicePasswordAck);
            return;
       } 
	   else
	   {
			ERRORLOG("第三次输入密码错误");
			verifyDevicePasswordAck.set_code(-30);
			verifyDevicePasswordAck.set_message("第三次输入密码错误");
			net_send_message<VerifyDevicePasswordAck>(msgdata, verifyDevicePasswordAck);
			return;
	   }  
    }
    else 
    {
        DEBUGLOG("HandleVerifyDevicePassword密码输入正确重置为0");
        pCPwdAttackChecker->Right();
		verifyDevicePasswordAck.set_code(0);
        verifyDevicePasswordAck.set_message("密码输入正确");
		net_send_message<VerifyDevicePasswordAck>(msgdata, verifyDevicePasswordAck);
    }

	if (hashOriPass != targetPassword) 
    {
        verifyDevicePasswordAck.set_code(-2);
        verifyDevicePasswordAck.set_message("password error!");
        net_send_message<VerifyDevicePasswordAck>(msgdata, verifyDevicePasswordAck);
        ERRORLOG("password error!");
        return;
    }
	return ;
}

/** 手机端连接矿机发起交易 */
void HandleCreateDeviceTxMsgReq( const std::shared_ptr<CreateDeviceTxMsgReq>& msg, const MsgData& msgdata )
{
	DEBUGLOG("HandleCreateDeviceTxMsgReq");
	// 手机端回执消息
	TxMsgAck txMsgAck;
	txMsgAck.set_version(getVersion());

	// 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{
		txMsgAck.set_code(-1);
		txMsgAck.set_message("version error!");
		net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);
		ERRORLOG("HandleCreateDeviceTxMsgReq IsVersionCompatible");
		return ;
	}

	// 判断矿机密码是否正确
    std::string password = msg->password();
    std::string hashOriPass = generateDeviceHashPassword(password);
    std::string targetPassword = Singleton<DevicePwd>::get_instance()->GetDevPassword();
	auto pCPwdAttackChecker = MagicSingleton<CPwdAttackChecker>::GetInstance(); 
  
    uint32_t minutescount ;
    bool retval = pCPwdAttackChecker->IsOk(minutescount);
    if(retval == false)
    {
        std::string minutescountStr = std::to_string(minutescount);
        txMsgAck.set_code(-31);
        txMsgAck.set_message(minutescountStr);
		net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);
        ERRORLOG("有连续3次错误，{}秒之后才可以输入", minutescount);
        return ;
    }

    if(hashOriPass.compare(targetPassword))
    {
        DEBUGLOG("输入密码错误开始记录次数");
       if(pCPwdAttackChecker->Wrong())
       {
            ERRORLOG("密码输入错误");
            txMsgAck.set_code(-5);
            txMsgAck.set_message("密码输入错误");
			net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);
            return ;
       }
	   else
	   {
			txMsgAck.set_code(-30);
			txMsgAck.set_message("第三次密码输入错误");
			net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);
			return ;
	   }
    }
    else 
    {
        DEBUGLOG("HandleCreateDeviceTxMsgReq密码输入正确重置为0");
        pCPwdAttackChecker->Right();
		// txMsgAck.set_code(0);
        // txMsgAck.set_message("密码输入正确");
		// net_send_message<TxMsgAck>(msgdata, txMsgAck);
    }

    if (hashOriPass != targetPassword) 
    {
        txMsgAck.set_code(-5);
        txMsgAck.set_message("password error!");
        net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);
        ERRORLOG("password error!");
        return;
    }

	// 判断各个字段是否合法
	if(msg->from().size() <= 0 || msg->to().size() <= 0 || msg->amt().size() <= 0 ||
		msg->minerfees().size() <= 0 || msg->needverifyprehashcount().size() <= 0)
	{
		txMsgAck.set_code(-2);
		txMsgAck.set_message("parameter error!");
		net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);

		ERRORLOG("HandleCreateDeviceTxMsgReq parameter error!");
		return ;
	}

	if( std::stod( msg->minerfees() ) <= 0 || 
		std::stoi( msg->needverifyprehashcount() ) < g_MinNeedVerifyPreHashCount ||
		std::stod( msg->amt() ) <= 0)
	{
		txMsgAck.set_code(-3);
		txMsgAck.set_message("minerfees or needverifyprehashcount error!");
		net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);

		ERRORLOG("HandleCreateDeviceTxMsgReq parameter error!");
		return ;
	}

	vector<string> Addr;
	Addr.push_back(msg->from());
	if (MagicSingleton<TxVinCache>::GetInstance()->IsConflict(Addr))
	{
		txMsgAck.set_code(-20);
		txMsgAck.set_message("The addr has being pengding!");
		net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);
		ERRORLOG("HandleCreateDeviceTxMsgReq CreateTx failed!!");
		return ;
	}

	int ret = CreateTx(msg->from().c_str(), msg->to().c_str(), msg->amt().c_str(), NULL, std::stoi(msg->needverifyprehashcount()), msg->minerfees().c_str());
	if(ret < 0)
	{
		txMsgAck.set_code(-4);
		txMsgAck.set_message("CreateTx failed!");
		net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);

		ERRORLOG("HandleCreateDeviceTxMsgReq CreateTx failed!!");
		return ;
	}

	txMsgAck.set_code(0);
	txMsgAck.set_message("CreateTx successful! Waiting for broadcast!");
	net_send_message<TxMsgAck>(msgdata, txMsgAck, net_com::Priority::kPriority_Middle_1);

	DEBUGLOG("HandleCreateDeviceTxMsgReq CreateTx successful! Waiting for broadcast! ");
	return ;
}


std::map<int32_t, std::string> GetCreateDeviceMultiTxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"),
												make_pair(-2, "三次密码输入错误"),
												make_pair(-3, "密码输入错误"),
												make_pair(-4, "第三次密码输入错误"),
												make_pair(-5, "密码不正确"),
												make_pair(-6, "发起地址参数错误"),
												make_pair(-7, "接收地址参数错误"),

												make_pair(-8, "创建交易时参数错误"),
												make_pair(-9, "创建交易时交易地址错误"),
												make_pair(-10, "创建交易时有之前交易挂起"),
												make_pair(-11, "创建交易时打开数据库错误"),
												make_pair(-12, "创建交易时获得打包费失败"),
												make_pair(-13, "创建交易时获得交易信息失败"),
												make_pair(-14, "创建交易时余额不足"),
												make_pair(-15, "创建交易时其他错误"),

												make_pair(-16, "打开数据库错误"),
												make_pair(-17, "获得打包费错误"),
												make_pair(-18, "获得主链错误"),
												};

	return errInfo;												
}

void HandleCreateDeviceMultiTxMsgReq(const std::shared_ptr<CreateDeviceMultiTxMsgReq>& msg, const MsgData& msgdata)
{
    TxMsgAck txMsgAck;
	auto errInfo = GetCreateDeviceMultiTxMsgReqCode();
    
    if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{		
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -1);
		return ;
	}

    // 判断矿机密码是否正确
    std::string password = msg->password();
    std::string hashOriPass = generateDeviceHashPassword(password);
    std::string targetPassword = Singleton<DevicePwd>::get_instance()->GetDevPassword();
    auto pCPwdAttackChecker = MagicSingleton<CPwdAttackChecker>::GetInstance(); 
   
    uint32_t minutescount ;
    bool retval = pCPwdAttackChecker->IsOk(minutescount);
    if(retval == false)
    {
		ERRORLOG("有连续3次错误，秒之后才可以输入", minutescount);
        std::string minutescountStr = std::to_string(minutescount);
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -2, minutescountStr);
        return;
    }

    if(hashOriPass.compare(targetPassword))
    {
        DEBUGLOG("输入密码错误开始记录次数");
       if(pCPwdAttackChecker->Wrong())
       {
            ERRORLOG("密码输入错误");
            ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -3);
            return;
       } 
       else
       {
			// 第三次密码输入错误
    		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -4);
            return;
       }
    }
    else 
    {
        DEBUGLOG("密码输入正确重置为0");
        pCPwdAttackChecker->Right();
    }
   
    if (hashOriPass != targetPassword) 
    {
		// 密码不正确
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -5);
        return;
    }

    if (0 != CheckAddrs<CreateDeviceMultiTxMsgReq>(msg))
    {
		// 发起方参数错误
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -6);
		return ;
    }

    std::vector<std::string> fromAddr;
    std::map<std::string, int64_t> toAddr;

    for (int i = 0; i < msg->from_size(); ++i)
    {
        std::string fromAddrStr = msg->from(i);
        fromAddr.push_back(fromAddrStr);
    }

    for (int i = 0; i < msg->to_size(); ++i)
    {
        ToAddr toAddrInfo = msg->to(i);
        int64_t amount = std::stod(toAddrInfo.amt()) * DECIMAL_NUM;
        toAddr.insert( make_pair(toAddrInfo.toaddr(), amount ) );
    }

    if(toAddr.size() != (size_t)msg->to_size())
    {
        // 接收方参数错误
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -7);
        return;
    }

    uint64_t gasFee = std::stod( msg->gasfees() ) * DECIMAL_NUM;
    uint32_t needVerifyPreHashCount = stoi( msg->needverifyprehashcount() );
    
    CTransaction outTx;
    int ret = TxHelper::CreateTxMessage(fromAddr,toAddr, needVerifyPreHashCount, gasFee, outTx);
	if(ret != 0)
	{
		ret -= 100;
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, ret);
		return ;
	}

    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
    Transaction* txn = pRocksDb->TransactionInit();
    if (txn == NULL)
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -8);
        return;
    }

    ON_SCOPE_EXIT
    {
		pRocksDb->TransactionDelete(txn, false);
	};

    uint64_t packageFee = 0;
    if ( 0 != pRocksDb->GetDevicePackageFee(packageFee) )
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -9);
        return ;
    }

    nlohmann::json txExtra = nlohmann::json::parse(outTx.extra());
    txExtra["TransactionType"] = TXTYPE_TX;	
    txExtra["NeedVerifyPreHashCount"] = needVerifyPreHashCount;
	txExtra["SignFee"] = gasFee;
    txExtra["PackageFee"] = packageFee;   // 本节点代发交易需要打包费

    outTx.set_extra(txExtra.dump());

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

    txMsg.set_tx(serTx);
	txMsg.set_txencodehash( encodeStrHash );

    std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -18);
        return;
    }
    txMsg.set_prevblkhash(blockHash);
    txMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));
    
	unsigned int top = 0;
	pRocksDb->GetBlockTop(txn, top);	
	txMsg.set_top(top);

    auto pTxMsg = make_shared<TxMsg>(txMsg);
	std::string txHash;
	ret = DoHandleTx(pTxMsg, txHash);
	txMsgAck.set_txhash(txHash);

	if (ret != 0)
	{
		ret -= 200;
	}
	DEBUGLOG("DoHandleTx ret:{}", ret);
	ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, ret);
}

std::map<int32_t, std::string> GetCreateMultiTxReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"), 
												make_pair(-2, "参数不合法"), 
												make_pair(-3, "交易双方地址错误"), 
												make_pair(-4, "获得交易双方地址错误"), 

												make_pair(-1001, "创建交易时参数错误"),
												make_pair(-1002, "创建交易时交易地址错误"),
												make_pair(-1003, "创建交易时有之前交易挂起"),
												make_pair(-1004, "创建交易时打开数据库错误"),
												make_pair(-1005, "创建交易时获得打包费失败"),
												make_pair(-1006, "创建交易时获得交易信息失败"),
												make_pair(-1007, "创建交易时余额不足"),

												make_pair(-5, "打开数据库错误"),
												make_pair(-6, "获得打包费错误"),
												
												};

	return errInfo;												
}
void HandleCreateMultiTxReq( const std::shared_ptr<CreateMultiTxMsgReq>& msg, const MsgData& msgdata )
{
    // 手机端回执消息体
    CreateMultiTxMsgAck createMultiTxMsgAck;
	auto errInfo = GetCreateMultiTxReqCode();

    // 判断版本是否兼容
    if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{
		ReturnAckCode<CreateMultiTxMsgAck>(msgdata, errInfo, createMultiTxMsgAck, -1);
		return ;
	}

    if (msg->from_size() > 1 && msg->to_size() > 1)
    {
        // 参数不合法
		ReturnAckCode<CreateMultiTxMsgAck>(msgdata, errInfo, createMultiTxMsgAck, -2);
		return ;
    }

	if (0 != CheckAddrs<CreateMultiTxMsgReq>(msg))
	{
		ReturnAckCode<CreateMultiTxMsgAck>(msgdata, errInfo, createMultiTxMsgAck, -3);
		return ;
	}

    CTransaction outTx;
    std::vector<std::string> fromAddr;
    std::map<std::string, int64_t> toAddr;

    int ret = GetAddrsFromMsg(msg, fromAddr, toAddr);
    if (0 != ret)
    {
		// 交易地址有错误
		ReturnAckCode<CreateMultiTxMsgAck>(msgdata, errInfo, createMultiTxMsgAck, -4);
        return ;
    }

    uint64_t minerFees = stod( msg->minerfees() ) * DECIMAL_NUM;
    uint32_t needVerifyPreHashCount = stoi( msg->needverifyprehashcount() );
    
    ret = TxHelper::CreateTxMessage(fromAddr, toAddr, needVerifyPreHashCount, minerFees, outTx);
    if(ret != 0)
	{
		ret -= 100;
        ReturnAckCode<CreateMultiTxMsgAck>(msgdata, errInfo, createMultiTxMsgAck, ret);
		return;
	}

    for(int i = 0;i <outTx.vin_size();i++)
    {
        CTxin *txin = outTx.mutable_vin(i);
        txin->clear_scriptsig();
    }

    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
    Transaction* txn = pRocksDb->TransactionInit();
    if (txn == NULL)
    {
        ReturnAckCode<CreateMultiTxMsgAck>(msgdata, errInfo, createMultiTxMsgAck, -5);
        return;
    }

    ON_SCOPE_EXIT
    {
		pRocksDb->TransactionDelete(txn, false);
	};

    uint64_t packageFee = 0;
    if ( 0 != pRocksDb->GetDevicePackageFee(packageFee) )
    {
        ReturnAckCode<CreateMultiTxMsgAck>(msgdata, errInfo, createMultiTxMsgAck, -6);
        return;
    }

    nlohmann::json extra;
    extra["TransactionType"] = TXTYPE_TX;
	extra["NeedVerifyPreHashCount"] = needVerifyPreHashCount;
	extra["SignFee"] = minerFees;
    extra["PackageFee"] = packageFee;   // 本节点代发交易需要打包费
	outTx.set_extra(extra.dump());

    std::string serTx = outTx.SerializeAsString();

	size_t encodeLen = serTx.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)serTx.data(), serTx.size(), encode);
	std::string encodeStr( (char *)encode, codeLen );

	std::string encodeStrHash = getsha256hash(encodeStr);

    createMultiTxMsgAck.set_txdata(encodeStr);
    createMultiTxMsgAck.set_txencodehash(encodeStrHash);
    
	ReturnAckCode<CreateMultiTxMsgAck>(msgdata, errInfo, createMultiTxMsgAck, 0);
}

std::map<int32_t, std::string> GetMultiTxReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"),
												make_pair(-2, "签名不正确"),
												make_pair(-3, "打开数据库错误"),
												make_pair(-4, "获得主链错误"),
												};

	return errInfo;												
}
void HandleMultiTxReq( const std::shared_ptr<MultiTxMsgReq>& msg, const MsgData& msgdata )
{
    TxMsgAck txMsgAck;

	auto errInfo = GetMultiTxReqCode();

    if( 0 != Util::IsVersionCompatible( msg->version() ) )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -1);
		return ;
	}

    unsigned char serTxCstr[msg->sertx().size()] = {0};
	unsigned long serTxCstrLen = base64_decode((unsigned char *)msg->sertx().data(), msg->sertx().size(), serTxCstr);
	std::string serTxStr((char *)serTxCstr, serTxCstrLen);

    CTransaction tx;
    tx.ParseFromString(serTxStr);

    std::vector<SignInfo> vSignInfo;
    for (int i = 0; i < msg->signinfo_size(); ++i)
    {
        SignInfo signInfo = msg->signinfo(i);
        vSignInfo.push_back(signInfo);
    }

    if (vSignInfo.size() <= 0)
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -2);
    }

    // 一对多交易只有一个发起方，取第0个
    SignInfo signInfo = msg->signinfo(0);
    unsigned char strsignatureCstr[signInfo.signstr().size()] = {0};
	unsigned long strsignatureCstrLen = base64_decode((unsigned char *)signInfo.signstr().data(), signInfo.signstr().size(), strsignatureCstr);

	unsigned char strpubCstr[signInfo.pubstr().size()] = {0};
	unsigned long strpubCstrLen = base64_decode((unsigned char *)signInfo.pubstr().data(), signInfo.pubstr().size(), strpubCstr);

    for (int i = 0; i < tx.vin_size(); ++i)
    {
        CTxin * txin = tx.mutable_vin(i);

        txin->mutable_scriptsig()->set_sign( strsignatureCstr, strsignatureCstrLen );
        txin->mutable_scriptsig()->set_pub( strpubCstr, strpubCstrLen );
    }

    auto extra = nlohmann::json::parse(tx.extra());
    int needVerifyPreHashCount = extra["NeedVerifyPreHashCount"].get<int>();

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -3);
		return;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

    std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -4);
        return;
    }

	std::string serTx = tx.SerializeAsString();
	unsigned int top = 0;
	pRocksDb->GetBlockTop(txn, top);
    
    TxMsg phoneToTxMsg;
    phoneToTxMsg.set_version(getVersion());
	phoneToTxMsg.set_tx(serTx);
	phoneToTxMsg.set_txencodehash(msg->txencodehash());
    phoneToTxMsg.set_prevblkhash(blockHash);
    phoneToTxMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));
	phoneToTxMsg.set_top(top);

	auto txmsg = make_shared<TxMsg>(phoneToTxMsg);
	std::string txHash;
	int ret = DoHandleTx(txmsg, txHash);
	txMsgAck.set_txhash(txHash);

	if(ret != 0)
	{
		ret -= 100;
	}
	DEBUGLOG("DoHandleTx ret:{}", ret);
	ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, ret);
	return;
}

std::map<int32_t, std::string> GetCreatePledgeTxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"), 
												make_pair(-2, "参数错误"), 
												make_pair(-3, "打开数据库错误"), 

												make_pair(-1001, "创建交易时参数错误"),
												make_pair(-1002, "创建交易时交易地址错误"),
												make_pair(-1003, "创建交易时有之前交易挂起"),
												make_pair(-1004, "创建交易时打开数据库错误"),
												make_pair(-1005, "创建交易时获得打包费失败"),
												make_pair(-1006, "创建交易时获得交易信息失败"),
												make_pair(-1007, "创建交易时余额不足"),
												};

	return errInfo;												
}
void HandleCreatePledgeTxMsgReq(const std::shared_ptr<CreatePledgeTxMsgReq>& msg, const MsgData &msgdata)
{
    CreatePledgeTxMsgAck createPledgeTxMsgAck; 
	auto errInfo = GetCreatePledgeTxMsgReqCode();

	if( 0 != Util::IsVersionCompatible( getVersion() ) )
	{
        ReturnAckCode<CreatePledgeTxMsgAck>(msgdata, errInfo, createPledgeTxMsgAck, -1);
		return ;
	}
   
    uint64_t gasFee = std::stod(msg->gasfees().c_str()) * DECIMAL_NUM;
    uint64_t amount = std::stod(msg->amt().c_str()) * DECIMAL_NUM;
    uint32_t needverifyprehashcount  = std::stoi(msg->needverifyprehashcount()) ;
  
    if(msg->addr().size()<= 0 || amount <= 0 || needverifyprehashcount < (uint32_t)g_MinNeedVerifyPreHashCount || gasFee <= 0)
    {
        ReturnAckCode<CreatePledgeTxMsgAck>(msgdata, errInfo, createPledgeTxMsgAck, -2);
        return ;
    }

    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if ( txn == NULL )
	{
        ReturnAckCode<CreatePledgeTxMsgAck>(msgdata, errInfo, createPledgeTxMsgAck, -3);
		return ;
	}

	ON_SCOPE_EXIT
    {
		pRocksDb->TransactionDelete(txn, false);
	};

    std::vector<std::string> fromAddr;
    fromAddr.push_back(msg->addr());

    std::map<std::string, int64_t> toAddr;
    toAddr[VIRTUAL_ACCOUNT_PLEDGE] = amount;

    CTransaction outTx;
    int ret = TxHelper::CreateTxMessage(fromAddr, toAddr,needverifyprehashcount , gasFee, outTx);
	if(ret != 0)
	{
		ret -= 100;
        ReturnAckCode<CreatePledgeTxMsgAck>(msgdata, errInfo, createPledgeTxMsgAck, ret);
		return ;
	}

    for(int i = 0;i <outTx.vin_size();i++)
    {
        CTxin *txin = outTx.mutable_vin(i);
        txin->clear_scriptsig();
    }

    nlohmann::json txInfo;
    txInfo["PledgeType"] = PLEDGE_NET_LICENCE;
    txInfo["PledgeAmount"] = amount;

    auto extra = nlohmann::json::parse(outTx.extra());
    extra["TransactionType"] = TXTYPE_PLEDGE;
	extra["TransactionInfo"] = txInfo;
	outTx.set_extra(extra.dump());
    std::string txData = outTx.SerializePartialAsString();

    size_t encodeLen = txData.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)txData.data(), txData.size(), encode);

    std::string encodeStr((char *)encode, codeLen);
	std::string txEncodeHash = getsha256hash(encodeStr);
    createPledgeTxMsgAck.set_txdata(encodeStr);
    createPledgeTxMsgAck.set_txencodehash(txEncodeHash);

	ReturnAckCode<CreatePledgeTxMsgAck>(msgdata, errInfo, createPledgeTxMsgAck, 0);
    
    return ;
}

std::map<int32_t, std::string> GetPledgeTxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"), 
												make_pair(-2, "参数错误"), 
												make_pair(-3, "打开数据库错误"), 
												make_pair(-4, "获得主链错误"),
												make_pair(-5, "获得最高高度错误"),

												};

	return errInfo;												
}
void HandlePledgeTxMsgReq(const std::shared_ptr<PledgeTxMsgReq>& msg, const MsgData &msgdata)
{
    TxMsgAck txMsgAck;

	auto errInfo = GetPledgeTxMsgReqCode();
   
	//判断版本是否兼容
	if( 0 != Util::IsVersionCompatible(msg->version() ) )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -1);
		return ;
	}

    if (msg->sertx().data() == nullptr || msg->sertx().size() == 0 || 
        msg->strsignature().data() == nullptr || msg->strsignature().size() == 0 || 
        msg->strpub().data() == nullptr || msg->strpub().size() == 0)
    {
   		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -2);
		return ;
    }

	// 将交易信息体，公钥，签名信息反base64
	unsigned char serTxCstr[msg->sertx().size()] = {0};
	unsigned long serTxCstrLen = base64_decode((unsigned char *)msg->sertx().data(), msg->sertx().size(), serTxCstr);
	std::string serTxStr((char *)serTxCstr, serTxCstrLen);

	CTransaction tx;
	tx.ParseFromString(serTxStr);

	unsigned char strsignatureCstr[msg->strsignature().size()] = {0};
	unsigned long strsignatureCstrLen = base64_decode((unsigned char *)msg->strsignature().data(), msg->strsignature().size(), strsignatureCstr);

	unsigned char strpubCstr[msg->strsignature().size()] = {0};
	unsigned long strpubCstrLen = base64_decode((unsigned char *)msg->strpub().data(), msg->strpub().size(), strpubCstr);

	for (int i = 0; i < tx.vin_size(); i++)
	{
		CTxin * txin = tx.mutable_vin(i);
		txin->mutable_scriptsig()->set_sign( std::string( (char *)strsignatureCstr, strsignatureCstrLen ) );
		txin->mutable_scriptsig()->set_pub( std::string( (char *)strpubCstr, strpubCstrLen ) );  
	}

    std::string serTx = tx.SerializeAsString();
	
    auto extra = nlohmann::json::parse(tx.extra());
    int needVerifyPreHashCount = extra["NeedVerifyPreHashCount"].get<int>();

	TxMsg phoneToTxMsg;
    phoneToTxMsg.set_version(getVersion());
	phoneToTxMsg.set_tx(serTx);
	phoneToTxMsg.set_txencodehash(msg->txencodehash());

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -3);
        return;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

    std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -4);
        return;
    }
    phoneToTxMsg.set_prevblkhash(blockHash);
    phoneToTxMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));

	unsigned int top = 0;
	int db_status = pRocksDb->GetBlockTop(txn, top);
    if (db_status) 
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -5);
        return;
    }	
	phoneToTxMsg.set_top(top);

	auto txmsg = make_shared<TxMsg>(phoneToTxMsg);
	std::string txHash;
	int ret = DoHandleTx(txmsg, txHash);
	txMsgAck.set_txhash(txHash);

	if (ret != 0)
	{
		ret -= 100;
	}
	DEBUGLOG("DoHandleTx ret:{}", ret);
	ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, ret);
    return ;
}


std::map<int32_t, std::string> GetCreateRedeemTxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"), 
												make_pair(-2, "参数错误"), 
												make_pair(-3, "交易被挂起"), 
												make_pair(-4, "打开数据库错误"), 
												make_pair(-5, "获得质押信息错误"),
												make_pair(-6, "账户未质押"),
												make_pair(-7, "查不到质押信息"),
												make_pair(-8, "质押信息错误"),
												make_pair(-9, "质押未超过30天期限"),
												make_pair(-10, "查询本地该账户质押信息失败"),
												make_pair(-11, "查询本地该账户无该质押信息"),
												make_pair(-12, "查询本地该账户无足够的utxo"),
												make_pair(-13, "获取打包费失败"),
												};

	return errInfo;												
}
void HandleCreateRedeemTxMsgReq(const std::shared_ptr<CreateRedeemTxMsgReq>& msg,const MsgData &msgdata)
{
    CreateRedeemTxMsgAck createRedeemTxMsgAck;

	auto errInfo = GetCreateRedeemTxMsgReqCode();

    // 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible( getVersion() ) )
	{
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -1);
		return ;
	}
    
    string fromAddr = msg->addr();
    uint64_t gasFee = std::stod(msg->gasfees().c_str()) * DECIMAL_NUM;
    uint64_t amount = std::stod(msg->amt().c_str()) * DECIMAL_NUM;
    uint32_t needverifyprehashcount  = std::stoi(msg->needverifyprehashcount()) ;
    string txhash = msg->txhash();
    
    if(fromAddr.size()<= 0 || amount <= 0 || needverifyprehashcount < (uint32_t)g_MinNeedVerifyPreHashCount || gasFee <= 0||txhash.empty())
    {
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -2);
        return ;
    }

	vector<string> Addr;
	Addr.push_back(fromAddr);
	if (MagicSingleton<TxVinCache>::GetInstance()->IsConflict(Addr))
	{
		ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -3);
		return ;
	}

    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if ( txn == NULL )
	{
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -4);
		return ;
	}

	ON_SCOPE_EXIT
    {
		pRocksDb->TransactionDelete(txn, false);
	};
    // 查询账号是否已经质押资产
    std::vector<string> addresses;
    int db_status = pRocksDb->GetPledgeAddress(txn, addresses);
    if(db_status != 0)
    {
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -5);
        return ;
    }

    auto iter = find(addresses.begin(), addresses.end(), fromAddr);
    if( iter == addresses.end() )
    {
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -6);
        return ;
    }

    CBlock cblock;
    string blockHeaderStr ;
    std::vector<string> utxoes;
    pRocksDb->GetPledgeAddressUtxo(txn,fromAddr, utxoes);
    if (utxoes.size() > 0)
    {
        std::string blockHash;
        pRocksDb->GetBlockHashByTransactionHash(txn, utxoes[0], blockHash); 
        int db_status1 = pRocksDb->GetBlockByBlockHash(txn,blockHash,blockHeaderStr);
    
        if(db_status1 != 0)
        {
            ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -7);
            return ;
        }
     }
    cblock.ParseFromString(blockHeaderStr);

    std::string utxoStr = msg->txhash();
    if (utxoStr.empty())
    {
        for (int i = 0; i < cblock.txs_size(); i++)
        {
            CTransaction tx = cblock.txs(i);
            if (CheckTransactionType(tx) == kTransactionType_Tx)
            {
                for (int j = 0; j < tx.vout_size(); j++)
                {   
                    CTxout vout = tx.vout(j);
                    if (vout.scriptpubkey() == VIRTUAL_ACCOUNT_PLEDGE)
                    {
                        utxoStr = tx.hash();
                    }
                }
            }
        }
    }

    if (utxoStr.empty())
    {
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -8);
		return ;   
    }

    //{{ Check redeem time, it must be more than 30 days, 20201209
    int result = IsMoreThan30DaysForRedeem(utxoStr);
    if (result != 0)
    {
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -9);
        return ;
    }
    //}}

    std::vector<string> utxos;
    db_status = pRocksDb->GetPledgeAddressUtxo(txn, fromAddr, utxos);
    if (db_status != 0)
    {
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -10);
        return ;
    }

    auto utxoIter = find(utxos.begin(), utxos.end(), utxoStr);
    if (utxoIter == utxos.end())
    {
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -11);
        return ;
    }
    CTransaction outTx;
    bool isTrue = FindUtxosFromRocksDb(fromAddr, fromAddr, 0, needverifyprehashcount, gasFee, outTx, utxoStr);
    for(int i = 0;i <outTx.vin_size();i++)
    {
        CTxin *txin = outTx.mutable_vin(i);
        txin->clear_scriptsig();
    }
    
	for (int i = 0; i != outTx.vin_size(); ++i)
	{
			CTxin * txin = outTx.mutable_vin(i);
			txin->clear_scriptsig();
	}

	outTx.clear_signprehash();
	outTx.clear_hash();

	if(!isTrue)
	{
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -12);
		return ;
	}

    uint64_t packageFee = 0;
    if ( 0 != pRocksDb->GetDevicePackageFee(packageFee) )
    {
        ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, -13);
		return ;
    }

    nlohmann::json txInfo;
    txInfo["RedeemptionUTXO"] = txhash;
    txInfo["ReleasePledgeAmount"] = amount;

	nlohmann::json extra;
    extra["fromaddr"] = fromAddr;
	extra["NeedVerifyPreHashCount"] = needverifyprehashcount;
	extra["SignFee"] = gasFee;
    extra["PackageFee"] = packageFee;   // 本节点代发交易需要打包费
	extra["TransactionType"] = TXTYPE_REDEEM;
    extra["TransactionInfo"] = txInfo;

	outTx.set_extra(extra.dump());
    std::string txData = outTx.SerializePartialAsString();

    size_t encodeLen = txData.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)txData.data(), txData.size(), encode);

    std::string encodeStr((char *)encode, codeLen);
	std::string txEncodeHash = getsha256hash(encodeStr);
    createRedeemTxMsgAck.set_txdata(encodeStr);
    createRedeemTxMsgAck.set_txencodehash(txEncodeHash);
    
	ReturnAckCode<CreateRedeemTxMsgAck>(msgdata, errInfo, createRedeemTxMsgAck, 0);
}


std::map<int32_t, std::string> GetRedeemTxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"), 
												make_pair(-2, "打开数据库错误"), 
												make_pair(-3, "获得最高高度错误"),
												make_pair(-4, "获得主链错误"),
												};

	return errInfo;												
}
void HandleRedeemTxMsgReq(const std::shared_ptr<RedeemTxMsgReq>& msg, const MsgData &msgdata )
{
    TxMsgAck txMsgAck; 
	auto errInfo = GetRedeemTxMsgReqCode();

    // 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible(getVersion() ) )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -1);
		return ;
	}
	// 将交易信息体，公钥，签名信息反base64
	unsigned char serTxCstr[msg->sertx().size()] = {0};
	unsigned long serTxCstrLen = base64_decode((unsigned char *)msg->sertx().data(), msg->sertx().size(), serTxCstr);
	std::string serTxStr((char *)serTxCstr, serTxCstrLen);

	CTransaction tx;
	tx.ParseFromString(serTxStr);

	unsigned char strsignatureCstr[msg->strsignature().size()] = {0};
	unsigned long strsignatureCstrLen = base64_decode((unsigned char *)msg->strsignature().data(), msg->strsignature().size(), strsignatureCstr);

	unsigned char strpubCstr[msg->strsignature().size()] = {0};
	unsigned long strpubCstrLen = base64_decode((unsigned char *)msg->strpub().data(), msg->strpub().size(), strpubCstr);

	for (int i = 0; i < tx.vin_size(); i++)
	{
		CTxin * txin = tx.mutable_vin(i);
		txin->mutable_scriptsig()->set_sign( std::string( (char *)strsignatureCstr, strsignatureCstrLen ) );
		txin->mutable_scriptsig()->set_pub( std::string( (char *)strpubCstr, strpubCstrLen ) );
	}

    std::string serTx = tx.SerializeAsString();
    auto extra = nlohmann::json::parse(tx.extra());
    int needVerifyPreHashCount = extra["NeedVerifyPreHashCount"].get<int>();

	TxMsg phoneToTxMsg;
    phoneToTxMsg.set_version(getVersion());
	phoneToTxMsg.set_tx(serTx);
	phoneToTxMsg.set_txencodehash(msg->txencodehash());

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -2);
        return;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	unsigned int top = 0;
	int db_status = pRocksDb->GetBlockTop(txn, top);	
    if (db_status) 
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -3);
        return;
    }
	phoneToTxMsg.set_top(top);

    std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -4);
        return;
    }
    phoneToTxMsg.set_prevblkhash(blockHash);
    phoneToTxMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));

	auto txmsg = make_shared<TxMsg>(phoneToTxMsg);
	std::string txHash;
	int ret = DoHandleTx(txmsg, txHash);
	txMsgAck.set_txhash(txHash);

	if (ret != 0)
	{
		ret -= 100;
	}
	DEBUGLOG("DoHandleTx ret:{}", ret);
	ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, ret);
    
    return; 
}

int CreatePledgeTransaction(const std::string & fromAddr,  const std::string & amount_str, uint32_t needVerifyPreHashCount, std::string gasFeeStr, std::string password, std::string pledgeType, std::string & txHash)
{
    uint64_t GasFee = std::stod(gasFeeStr.c_str()) * DECIMAL_NUM;
    uint64_t amount = std::stod(amount_str) * DECIMAL_NUM;
    if(fromAddr.size() <= 0 || amount <= 0 || needVerifyPreHashCount < (uint32_t)g_MinNeedVerifyPreHashCount || GasFee <= 0)
    {
        return -1;
    }

    // // 判断矿机密码是否正确
    std::string hashOriPass = generateDeviceHashPassword(password);
    std::string targetPassword = Singleton<DevicePwd>::get_instance()->GetDevPassword();
    
    if (hashOriPass != targetPassword) 
    {
        return -2;
    }

    vector<string> Addr;
	Addr.push_back(fromAddr);
	if (MagicSingleton<TxVinCache>::GetInstance()->IsConflict(Addr))
	{
		return -3;
	}

    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if ( txn == NULL )
	{
		return -4;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

    CTransaction outTx;
    bool isTrue = FindUtxosFromRocksDb(fromAddr, VIRTUAL_ACCOUNT_PLEDGE, amount, needVerifyPreHashCount, GasFee, outTx);
	if(!isTrue)
	{
		return -5;
	}

    nlohmann::json txInfo;
    txInfo["PledgeType"] = pledgeType;
    txInfo["PledgeAmount"] = amount;

    nlohmann::json extra;
    extra["NeedVerifyPreHashCount"] = needVerifyPreHashCount;
    extra["SignFee"] = GasFee;
    extra["PackageFee"] = 0;   // 本节点自身发起无需打包费
    extra["TransactionType"] = TXTYPE_PLEDGE;
    extra["TransactionInfo"] = txInfo;

    outTx.set_extra(extra.dump());

    for (int i = 0; i < outTx.vin_size(); i++)
	{
		CTxin * txin = outTx.mutable_vin(i);;
		txin->clear_scriptsig();
	}

	std::string serTx = outTx.SerializeAsString();

	size_t encodeLen = serTx.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)serTx.data(), serTx.size(), encode);
	std::string encodeStr( (char *)encode, codeLen );

	std::string encodeStrHash = getsha256hash(encodeStr);

    if (!g_AccountInfo.SetKeyByBs58Addr(g_privateKey, g_publicKey, fromAddr.c_str())) 
    {
        return -6;
    }

	std::string signature;
	std::string strPub;
	GetSignString(encodeStrHash, signature, strPub);

	for (int i = 0; i < outTx.vin_size(); i++)
	{
		CTxin * txin = outTx.mutable_vin(i);
		txin->mutable_scriptsig()->set_sign(signature);
		txin->mutable_scriptsig()->set_pub(strPub);
	}

	serTx = outTx.SerializeAsString();

	TxMsg txMsg;
    txMsg.set_version( getVersion() );
	txMsg.set_tx(serTx);
	txMsg.set_txencodehash( encodeStrHash );

	unsigned int top = 0;
	int db_status = pRocksDb->GetBlockTop(txn, top);
    if (db_status) 
    {
        return -7;
    }	
	txMsg.set_top(top);

    std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        return -8;
    }
    txMsg.set_prevblkhash(blockHash);
    txMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));

	auto msg = make_shared<TxMsg>(txMsg);
    int ret = DoHandleTx(msg, txHash);

    if (ret != 0)
	{
		ret -= 100;
	}
	DEBUGLOG("DoHandleTx ret:{}", ret);
    return ret;
}

std::map<int32_t, std::string> GetCreateDevicePledgeTxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"), 
												make_pair(-2, "密码错误倒计时未结束"), 
												make_pair(-3, "密码错误"),
												make_pair(-4, "密码第三次输入错误"),

												};

	return errInfo;												
}
void HandleCreateDevicePledgeTxMsgReq(const std::shared_ptr<CreateDevicePledgeTxMsgReq>& msg, const MsgData &msgdata )
{
    TxMsgAck txMsgAck;
	auto errInfo = GetCreateDevicePledgeTxMsgReqCode();

	// 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible(getVersion() ) )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -1);
		return ;
	}
	
	std::string hashOriPass = generateDeviceHashPassword(msg->password());
    std::string targetPassword = Singleton<DevicePwd>::get_instance()->GetDevPassword();
  
  	auto pCPwdAttackChecker = MagicSingleton<CPwdAttackChecker>::GetInstance(); 
    uint32_t minutescount = 0;
    bool retval = pCPwdAttackChecker->IsOk(minutescount);
    if(retval == false)
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -2, std::to_string(minutescount));
        return ;
    }

    if(hashOriPass.compare(targetPassword))
    {
        DEBUGLOG("输入密码错误开始记录次数");
       if(pCPwdAttackChecker->Wrong())
       {
            ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -3);
            return;
       }
       else
       {
            ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -4);
            return;
       }   
    }
    else 
    {
        DEBUGLOG("输入密码成功重置为0");
        pCPwdAttackChecker->Right();
    }


	std::string txHash;
	int ret = CreatePledgeTransaction(msg->addr(), msg->amt(), std::stoi(msg->needverifyprehashcount()), msg->gasfees(), msg->password(), PLEDGE_NET_LICENCE, txHash);
	txMsgAck.set_txhash(txHash);

	if (ret != 0)
	{
		ret -= 1000;
	}

	ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, ret);
    return ;
}

int CreateRedeemTransaction(const std::string & fromAddr, uint32_t needVerifyPreHashCount, std::string gasFeeStr, std::string utxo, std::string password, std::string & txHash)
{
    // 参数判断
    uint64_t GasFee = std::stod(gasFeeStr.c_str()) * DECIMAL_NUM;
    if(fromAddr.size() <= 0 || needVerifyPreHashCount < (uint32_t)g_MinNeedVerifyPreHashCount || GasFee <= 0 || utxo.empty())
    {
        return -1;
    }

    // 判断矿机密码是否正确
    std::string hashOriPass = generateDeviceHashPassword(password);
    std::string targetPassword = Singleton<DevicePwd>::get_instance()->GetDevPassword();
    if (hashOriPass != targetPassword) 
    {
        return -2;
    }

    vector<string> Addr;
	Addr.push_back(fromAddr);
	if (MagicSingleton<TxVinCache>::GetInstance()->IsConflict(Addr))
	{
		return -3;
	}

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		return -4;
	}

    ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

    // 查询账号是否已经质押资产
    std::vector<string> addresses;
    int db_status = pRocksDb->GetPledgeAddress(txn, addresses);
    if(db_status != 0)
    {
        return -5;
    }
    auto iter = find(addresses.begin(), addresses.end(), fromAddr);
    if( iter == addresses.end() )
    {
        return -6;
    }
   
    std::vector<string> utxos;
    db_status = pRocksDb->GetPledgeAddressUtxo(txn, fromAddr, utxos);
    if (db_status != 0)
    {
        return -7;
    }

    auto utxoIter = find(utxos.begin(), utxos.end(), utxo);
    if (utxoIter == utxos.end())
    {
        return -8;
    }

    //{{ Check time of the redeem, redeem time must be more than 30 days, add 20201208   LiuMingLiang
    int result = IsMoreThan30DaysForRedeem(utxo);
    if (result != 0)
    {
        return -9;
    }
    //}}End

    CTransaction outTx;
    bool isTrue = FindUtxosFromRocksDb(fromAddr, fromAddr, 0, needVerifyPreHashCount, GasFee, outTx, utxo);
	if(!isTrue)
	{
        return -10;
	}

    nlohmann::json txInfo;
    txInfo["RedeemptionUTXO"] = utxo;

    nlohmann::json extra;
    extra["NeedVerifyPreHashCount"] = needVerifyPreHashCount;
    extra["SignFee"] = GasFee;
    extra["PackageFee"] = 0;   // 本节点自身发起无需打包费
    extra["TransactionType"] = TXTYPE_REDEEM;
    extra["TransactionInfo"] = txInfo;

	outTx.set_extra(extra.dump());

	std::string serTx = outTx.SerializeAsString();

	size_t encodeLen = serTx.size() * 2 + 1;
	unsigned char encode[encodeLen] = {0};
	memset(encode, 0, encodeLen);
	long codeLen = base64_encode((unsigned char *)serTx.data(), serTx.size(), encode);
	std::string encodeStr( (char *)encode, codeLen );

	std::string encodeStrHash = getsha256hash(encodeStr);

    // 设置默认账号为发起账号
    if (!g_AccountInfo.SetKeyByBs58Addr(g_privateKey, g_publicKey, fromAddr.c_str())) 
    {
        return -11;
    }

	std::string signature;
	std::string strPub;
	GetSignString(encodeStrHash, signature, strPub);

	for (int i = 0; i < outTx.vin_size(); i++)
	{
		CTxin * txin = outTx.mutable_vin(i);
		txin->mutable_scriptsig()->set_sign(signature);
		txin->mutable_scriptsig()->set_pub(strPub);
	}

	serTx = outTx.SerializeAsString();
	
	TxMsg txMsg;
	txMsg.set_version( getVersion() );

	txMsg.set_tx(serTx);
	txMsg.set_txencodehash( encodeStrHash );

	unsigned int top = 0;
	db_status = pRocksDb->GetBlockTop(txn, top);
    if (db_status) 
    {
        return -12;
    }
	txMsg.set_top(top);

    std::string blockHash;
    if ( 0 != pRocksDb->GetBestChainHash(txn, blockHash) )
    {
        return -13;
    }
    txMsg.set_prevblkhash(blockHash);
    txMsg.set_trycountdown(CalcTxTryCountDown(needVerifyPreHashCount));

	auto msg = make_shared<TxMsg>(txMsg);
    int ret = DoHandleTx(msg, txHash);

	if (ret != 0)
	{
		ret -= 100;
	}
	DEBUGLOG("DoHandleTx ret:{}", ret);
    return ret;
}


std::map<int32_t, std::string> GetCreateDeviceRedeemTxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {make_pair(0, "成功"), 
												make_pair(-1, "版本不兼容"), 
												make_pair(-2, "密码错误倒计时未结束"), 
												make_pair(-3, "密码错误"),
												make_pair(-4, "密码第三次输入错误"),
												};

	return errInfo;												
}

// 手机连接矿机发起解质押交易
void HandleCreateDeviceRedeemTxMsgReq(const std::shared_ptr<CreateDeviceRedeemTxReq> &msg, const MsgData &msgdata )
{
	TxMsgAck txMsgAck;
	auto errInfo = GetCreateDeviceRedeemTxMsgReqCode();

	// 判断版本是否兼容
	if( 0 != Util::IsVersionCompatible(getVersion() ) )
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -1);
		return ;
	}
	
	std::string hashOriPass = generateDeviceHashPassword(msg->password());
    std::string targetPassword = Singleton<DevicePwd>::get_instance()->GetDevPassword();
  
  	auto pCPwdAttackChecker = MagicSingleton<CPwdAttackChecker>::GetInstance(); 
    uint32_t minutescount = 0;
    bool retval = pCPwdAttackChecker->IsOk(minutescount);
    if(retval == false)
    {
        ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -2, std::to_string(minutescount));
        return;
    }

    if(hashOriPass.compare(targetPassword))
    {
        DEBUGLOG("输入密码错误开始记录次数");
       if(pCPwdAttackChecker->Wrong())
       {
            ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -3);
            return;
       }
       else
       {
            ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, -4);
            return;
       }   
    }
    else 
    {
        DEBUGLOG("输入密码成功重置为0");
        pCPwdAttackChecker->Right();
    }

	std::string txHash;
    int ret = CreateRedeemTransaction(msg->addr(), std::stoi(msg->needverifyprehashcount()), msg->gasfees(), msg->utxo(), msg->password(), txHash);
	txMsgAck.set_txhash(txHash);

	if (ret != 0)
	{
		ret -= 1000;
	}

	ReturnAckCode<TxMsgAck>(msgdata, errInfo, txMsgAck, ret);
    return ;
}

template<typename Ack>
void ReturnAckCode(const MsgData& msgdata, std::map<int32_t, std::string> errInfo, Ack & ack, int32_t code, const std::string & extraInfo)
{
	ack.set_version(getVersion());
	ack.set_code(code);
	if (extraInfo.size())
	{
		ack.set_message(extraInfo);
	}
	else
	{
		ack.set_message(errInfo[code]);
	}

	net_send_message<Ack>(msgdata, ack, net_com::Priority::kPriority_High_1); // ReturnAckCode大部分处理交易，默认优先级为high1
}

template<typename TxReq> 
int CheckAddrs( const std::shared_ptr<TxReq>& req)
{
	if (req->from_size() > 1 && req->to_size() > 1)
    {
		return -1;
    }
	if (req->from_size() == 0 || req->to_size() == 0)
    {
		return -2;
    }
	return 0;
}

int GetAddrsFromMsg( const std::shared_ptr<CreateMultiTxMsgReq>& msg, 
                     std::vector<std::string> &fromAddr,
                     std::map<std::string, int64_t> &toAddr)
{
    for (int i = 0; i < msg->from_size(); ++i)
    {
        std::string fromAddrStr = msg->from(i);
        fromAddr.push_back(fromAddrStr);
    }

    for (int i = 0; i < msg->to_size(); ++i)
    {
        ToAddr toAddrInfo = msg->to(i);
        if (toAddrInfo.toaddr().empty() && toAddrInfo.amt().empty())
        {
            ERRORLOG("parse error! toaddr or amt is empty!");
            return -1;
        }

        int64_t amount = std::stod(toAddrInfo.amt()) * DECIMAL_NUM;
        toAddr.insert( make_pair(toAddrInfo.toaddr(), amount ) );
    }

    if (fromAddr.size() == 0 || toAddr.size() == 0)
    {
        return -2;
    }

    if (toAddr.size() != (size_t)msg->to_size())
    {
        return -3;
    }

    return 0;
}

// Check time of the redeem, redeem time must be more than 30 days, add 20201208   LiuMingLiang
int IsMoreThan30DaysForRedeem(const std::string& utxo)
{
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if (txn == NULL)
	{
		return -1;
	}

    ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, false);
	};

    std::string strTransaction;
    int db_status = pRocksDb->GetTransactionByHash(txn, utxo, strTransaction);
    if (db_status != 0)
    {
        return -1;
    }

    CTransaction utxoPledge;
    utxoPledge.ParseFromString(strTransaction);
    uint64_t nowTime = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
    static const uint64_t DAYS30 = (uint64_t)1000000 * 60 * 60 * 24 * 30;
    if ((nowTime - utxoPledge.time()) >= DAYS30)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

// Create: Check chain height of the all node, 20210225
int CheckAllNodeChainHeightInReasonableRange()
{
	// Get chain height
    unsigned int chainHeight = get_chain_height();
	if (chainHeight == 0)
	{
		return -3;
	}

	unsigned int reasonableCount = 0;
	std::vector<Node> nodelist;
	if (Singleton<PeerNode>::get_instance()->get_self_node().is_public_node)
	{
		nodelist = Singleton<PeerNode>::get_instance()->get_nodelist();
	}
	else
	{
		nodelist = Singleton<NodeCache>::get_instance()->get_nodelist();
	}
	if (nodelist.empty())
	{
		return -2;
	}
	for (auto& node : nodelist)
	{
		DEBUGLOG("Node chain height: node.id:{} node.chain_height:{} chainHeight:{}", node.id, node.chain_height, chainHeight);
		int difference = node.chain_height - chainHeight;
		if (abs(difference) <= REASONABLE_HEIGHT_RANGE)
		{
			++reasonableCount;
		}
	}

	float fTotalCount = nodelist.size();
	float fReasonableCount = reasonableCount;
	static const float STANDARD_VALUE = 0.60;
	bool result = ((fReasonableCount / fTotalCount) >= STANDARD_VALUE);
	DEBUGLOG("Check chain height: fReasonableCount:{} fTotalCount:{} result:{}", fReasonableCount, fTotalCount, result);

	return result ? 0 : -1;
}

// Description: handle the ConfirmTransactionReq from network,   20210309   Liu
void HandleConfirmTransactionReq(const std::shared_ptr<ConfirmTransactionReq>& msg, const MsgData& msgdata)
{
	std::string version = msg->version();
	std::string id = msg->id();
	std::string txHash = msg->tx_hash();
	
	bool success = false;
	CBlock block;

	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if (txn != nullptr)
	{
		std::string txRaw;
		int db_status = pRocksDb->GetTransactionByHash(txn, txHash, txRaw);
		if (db_status == 0)
		{
			success = true;
			string blockHash;
			pRocksDb->GetBlockHashByTransactionHash(txn, txHash, blockHash);
			string blockRaw;
			pRocksDb->GetBlockByBlockHash(txn, blockHash, blockRaw);
			block.ParseFromString(blockRaw);
			DEBUGLOG("In confirm transaction, Get block success.", blockHash);
		}
		pRocksDb->TransactionDelete(txn, true);
	}

	ConfirmTransactionAck ack;
	ack.set_version(getVersion());
	ack.set_id(net_get_self_node_id());
	ack.set_tx_hash(txHash);
	ack.set_flag(msg->flag());

	if (success)
	{
		ack.set_success(true);
		std::string blockRaw = block.SerializeAsString();
		ack.set_block_raw(blockRaw);
	}
	else
	{
		ack.set_success(false);
	}

	net_send_message<ConfirmTransactionAck>(id, ack);
}

void HandleConfirmTransactionAck(const std::shared_ptr<ConfirmTransactionAck>& msg, const MsgData& msgdata)
{
	std::string ver = msg->version();
	std::string id = msg->id();
	std::string tx_hash = msg->tx_hash();
	bool success = msg->success();
	DEBUGLOG("Receive confirm: id:{} tx_hash:{} success:{} ", id, tx_hash, success);
	if (success)
	{
		std::string blockRaw = msg->block_raw();
		CBlock block;
		block.ParseFromString(blockRaw);

		if (msg->flag() == ConfirmTxFlag)
		{
			MagicSingleton<TransactionConfirmTimer>::GetInstance()->update_count(tx_hash, block);
		}
		else if (msg->flag() == ConfirmRpcFlag)
		{
			if (g_RpcTransactionConfirm.is_not_exist_id(tx_hash, id))
			{
				g_RpcTransactionConfirm.update_count(tx_hash, block);
				g_RpcTransactionConfirm.update_id(tx_hash,id);
			}
		}
	}
	else
	{
		if (msg->flag() == ConfirmTxFlag)
		{
			MagicSingleton<TransactionConfirmTimer>::GetInstance()->update_failed_count(tx_hash);
		}
		else if (msg->flag() == ConfirmRpcFlag)
		{
			if (g_RpcTransactionConfirm.is_not_exist_id(tx_hash, id))
			{
				g_RpcTransactionConfirm.update_failed_count(tx_hash);
				g_RpcTransactionConfirm.update_id(tx_hash,id);
			}
		}
	}
}

void SendTransactionConfirm(const std::string& tx_hash, ConfirmCacheFlag flag, const uint32_t confirmCount)
{
	if (confirmCount == 0)
	{
		ERRORLOG("confirmCount is empty");
		return;
	}

	ConfirmTransactionReq req;
	req.set_version(getVersion());
	req.set_id(net_get_self_node_id());
	req.set_tx_hash(tx_hash);
	req.set_flag(flag);

	std::vector<Node> list;
	if (Singleton<PeerNode>::get_instance()->get_self_node().is_public_node)
	{
		list = Singleton<PeerNode>::get_instance()->get_nodelist();
	}
	else
	{
		list = Singleton<NodeCache>::get_instance()->get_nodelist();
	}

	std::random_device device;
	std::mt19937 engine(device());

	int send_size = std::min(list.size(), (size_t)confirmCount);

	int count = 0;
	while (count < send_size && !list.empty())
	{
		int index = engine() % list.size();

		net_send_message<ConfirmTransactionReq>(list[index].id, req);
		++count;
		DEBUGLOG("Send to confirm: {} {} {} ", index, list[index].id, count);

		list.erase(list.begin() + index);
	}
}
