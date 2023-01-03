
#include <algorithm>
#include <iterator>
#include <pthread.h>

#include "ca_transaction.h"
#include "ca_global.h"
#include "ca_hexcode.h"
#include "ca_rocksdb.h"
#include "ca_blockpool.h"
#include "ca_console.h"
#include "ca_synchronization.h"
#include "ca_base58.h"
#include "ca_rollback.h"

#include "MagicSingleton.h"
#include "../include/logging.h"
#include "../include/ScopeGuard.h"

bool BlockPoll::CheckConflict(const CBlock& block1, const CBlock& block2)
{
	std::vector<std::string> v1;
	{
		CTransaction tx = block1.txs(0);
		for(int j = 0; j < tx.vin_size(); j++)
		{
			CTxin vin = tx.vin(j);
			std::string hash = vin.prevout().hash();
			if(hash.size() > 0)
			{
				v1.push_back(hash + "_" + GetBase58Addr(vin.scriptsig().pub()));
			}
		}
	}

	std::vector<std::string> v2;
	{
		CTransaction tx = block2.txs(0);
		for(int j = 0; j < tx.vin_size(); j++)
		{
			CTxin vin = tx.vin(j);
			std::string hash = vin.prevout().hash();
			if(hash.size() > 0)
			{
				v2.push_back(hash + "_" + GetBase58Addr(vin.scriptsig().pub()));
			}
		}
	}

    std::sort(v1.begin(), v1.end());
    std::sort(v2.begin(), v2.end());
 
    std::vector<std::string> v_intersection;
 
    std::set_intersection(v1.begin(), v1.end(),
                          v2.begin(), v2.end(),
                          std::back_inserter(v_intersection));
	return v_intersection.size() > 0 ;
}


bool BlockPoll::CheckConflict(const CBlock& block)
{
	for (auto it = blocks_.begin(); it != blocks_.end(); ++it) 
	{
		auto &curr_block = *it;
		bool ret = CheckConflict(curr_block.blockheader_, block);
		if(ret)   //有冲突
		{
			return true;
		}
	}
	return false;
}

bool BlockPoll::Add(const Block& block)
{
	std::lock_guard<std::mutex> lck(mu_block_);

	if(block.isSync_)
	{
		INFOLOG("BlockPoll::Add sync=====height:{}, hash:{}", block.blockheader_.height(), block.blockheader_.hash().substr(0,HASH_LEN));

		sync_blocks_.push_back(block);
		return false;
	}
	CBlock blockheader = block.blockheader_;

	if(!VerifyHeight(blockheader))
	{
		ERRORLOG("BlockPoll:VerifyHeight fail!!");
		return false;
	}  

	//检查utxo是否有冲突
	for (auto it = blocks_.begin(); it != blocks_.end(); ++it) 
	{
		auto &curr_block = *it;
		bool ret = CheckConflict(curr_block.blockheader_, blockheader);
		if(ret)   //有冲突
		{
			ERRORLOG("BlockPoll::Add====has conflict");
			if(curr_block.blockheader_.time() < blockheader.time())   //预留块中的早
			{
				return false;
			}
			else
			{     //预留块中的晚
				it = blocks_.erase(it);
				blocks_.push_back(block);
				return true;
			}
		}
	}
	INFOLOG("BlockPoll::Add sync=====height:{}, hash:{}", blockheader.height(), blockheader.hash().substr(0,HASH_LEN));
	blocks_.push_back(block);
	return true;
}



void BlockPoll::Process()
{
	if(processing_)
	{
		DEBUGLOG("BlockPoll::Process is processing_");
		return;
	}
	processing_ = true;
	std::lock_guard<std::mutex> lck(mu_block_);
	int success_num = 0;
	std::string frist_hash;
	int frist_hash_num = 0;
	if(sync_blocks_.size() > 0)
	{
		frist_hash = sync_blocks_.front().blockheader_.prevhash();
	}
	bool sync_add_success = false; 
	g_synch->sync_adding = false;

    auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
    Transaction* txn = pRocksDb->TransactionInit();
	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, true);
	};

	// 同步数据起始高度
	uint64_t startHeight = 0;
	uint64_t endHeight = 0;

    for (auto it = sync_blocks_.begin(); it != sync_blocks_.end(); ++it) 
	{
		g_synch->sync_adding = true;
        auto &block = *it;
		if(frist_hash == block.blockheader_.prevhash())
		{
			frist_hash_num++;
		}

		// 取出同步数据中起始块高度
		if (startHeight == 0)
		{
			startHeight = block.blockheader_.height();
		}
		else
		{
			if ( (uint64_t)block.blockheader_.height() < startHeight )
			{
				startHeight = block.blockheader_.height();
			}
		}

		// 取出同步数据中结束块高度
		if (endHeight == 0) 
		{ 
			endHeight = block.blockheader_.height(); 
		}
		else
		{
			if ( (uint64_t)block.blockheader_.height() > startHeight )
			{
				endHeight = block.blockheader_.height();
			}
		}
		
		if(VerifyBlockHeader(block.blockheader_))
		{
			bool ret = AddBlock(block.blockheader_);
			if(ret)
			{
                /* 交易统计增加 */
                // 交易
                uint64_t counts{0};
                pRocksDb->GetTxCount(txn, counts);
                counts++;
                pRocksDb->SetTxCount(txn, counts);
                // 燃料费
                counts = 0;
                pRocksDb->GetGasCount(txn, counts);
                counts++;
                pRocksDb->SetGasCount(txn, counts);
                // 额外奖励
                counts = 0;
                pRocksDb->GetAwardCount(txn, counts);
                counts++;
                pRocksDb->SetAwardCount(txn, counts);

				sync_add_success = true;
				success_num++;
				ca_console successColor(kConsoleColor_Green, kConsoleColor_Black, true);
				DEBUGLOG("Sync block: {} is successful!\n", block.blockheader_.hash().c_str());
			}
		}
    }
	g_synch->sync_adding = false;
	if(sync_blocks_.size() > 0)
	{	
		DEBUGLOG("frist_hash_num:{}", frist_hash_num);
	}
	int sync_cnt = Singleton<Config>::get_instance()->GetSyncDataCount();
	
	if((success_num + frist_hash_num) >= sync_cnt)
	{
		int sync_cnt = Singleton<Config>::get_instance()->GetSyncDataCount();
		g_synch->DataSynch(g_synch->verifying_node.id, sync_cnt);
		DEBUGLOG("sync not over, continue sync,id:{}", g_synch->verifying_node.id);
	}

	unsigned int blockHeight = 0;
	if (0 != pRocksDb->GetBlockTop(txn, blockHeight))
	{
		processing_ = false;
		return ;
	}

	TRACELOG("g_synch->conflict_height : {}", g_synch->conflict_height );
 
	if(sync_blocks_.size() >= SYNC_ADD_FAIL_LIMIT && !sync_add_success)
	{
		// 同步失败计次
		sync_add_fail_times_++;
		DEBUGLOG("sync fail - sync_add_fail_times_:{}", sync_add_fail_times_);
	}
	else if(sync_blocks_.size() > 0 && sync_add_success)
	{
		// 同步成功时清零
		sync_add_fail_times_ = 0;
	}

	if ( (sync_blocks_.size() > 0) && 
		(g_synch->conflict_height > -1) && 
		(g_synch->conflict_height < (int)blockHeight - SYNC_ADD_FAIL_LIMIT) )
	{
		// 有分叉点的时候计次
		sync_fork_fail_times_++;
		DEBUGLOG("fork fail - sync_fork_fail_times_:{}", sync_fork_fail_times_);
	}

	std::vector<Block> syncBlockTmp = sync_blocks_;
	sync_blocks_.clear();

	if(sync_add_fail_times_ >= SYNC_ADD_FAIL_TIME || sync_fork_fail_times_ >= SYNC_ADD_FAIL_TIME)
	{
		ERRORLOG("BlockPoll::Process rollback");
		unsigned int top = 0;
		pRocksDb->GetBlockTop(txn, top);

		uint32_t rollbackHight = top;
		if(g_synch->conflict_height > -1 && (unsigned)g_synch->conflict_height < top)
		{
			rollbackHight = startHeight > (uint64_t)g_synch->conflict_height ? startHeight : g_synch->conflict_height;
		}
		else
		{
			rollbackHight = top - ROLLBACK_HEIGHT;
		}

		if (syncBlockTmp.size() != 0)
		{
			if (startHeight < top)
			{
				if ( 0 != MagicSingleton<Rollback>::GetInstance()->RollbackToHeight(startHeight) )
				{
					processing_ = false;
					return;
				}
			}

			if ( 0 != MagicSingleton<Rollback>::GetInstance()->RollbackBlockBySyncBlock(rollbackHight, syncBlockTmp) )
			{
				processing_ = false;
				return;
			}

			// 更新top
			Singleton<PeerNode>::get_instance()->set_self_chain_height();

			std::lock_guard<std::mutex> lck(rollbackLock);
			rollbackCount++;
		}
		sync_add_fail_times_ = 0;
		sync_fork_fail_times_ = 0;
	}

	// g_synch->conflict_height = -1; // need to lock

    for (auto it = blocks_.begin(); it != blocks_.end(); ) 
	{ 
        auto &block = *it;
		if(time(NULL) - block.time_ >= PROCESS_TIME)
		{
			block.time_ = time(NULL);
			pending_block_.push_back(std::move(block));
			it = blocks_.erase(it);
		}else{
			++it; 
		}
    }

	if(pending_block_.size() == 0)
	{
		processing_ = false;
		return;
	}
	std::sort(pending_block_.begin(), pending_block_.end(), [](const Block & b1, const Block & b2){
		if (b1.blockheader_.height() < b2.blockheader_.height())
		{
			return true;
		}
		else
		{
			return false;
		}
	});
	

	// auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	// Transaction* txn = pRocksDb->TransactionInit();

    for (auto it = pending_block_.begin(); it != pending_block_.end(); ) 
	{
        auto &block = *it;
		std::string strTempHeader;
		pRocksDb->GetBlockByBlockHash(txn, block.blockheader_.hash(), strTempHeader);

		if (strTempHeader.size() != 0)
		{
			it = pending_block_.erase(it);
			continue;
		}

		std::string strPrevHeader;
		pRocksDb->GetBlockByBlockHash(txn, block.blockheader_.prevhash(), strPrevHeader);
		if (strPrevHeader.size() == 0)
		{
			++it;
			continue;
		}
		//过期
		if(time(NULL) - block.time_ >= PENDING_EXPIRE_TIME)
		{
			TRACELOG("pending_block_  have expire");
			it = pending_block_.erase(it);
			continue;
		}

		if(VerifyBlockHeader(block.blockheader_))
		{
			bool ret = AddBlock(block.blockheader_);
			if(ret)
			{
                /* 交易统计增加 */
                // 交易
                uint64_t counts{0};
                pRocksDb->GetTxCount(txn, counts);
                counts++;
                pRocksDb->SetTxCount(txn, counts);
                // 燃料费
                counts = 0;
                pRocksDb->GetGasCount(txn, counts);
                counts++;
                pRocksDb->SetGasCount(txn, counts);
                // 额外奖励
                counts = 0;
                pRocksDb->GetAwardCount(txn, counts);
                counts++;
                pRocksDb->SetAwardCount(txn, counts);

				ca_console successColor(kConsoleColor_Green, kConsoleColor_Black, true);
				INFOLOG("Add block: {} is successful!", block.blockheader_.hash().c_str());
			}
		}
		it = pending_block_.erase(it);
    }
	processing_ = false;
}


std::string BlockPoll::GetBlock()
{
	std::lock_guard<std::mutex> lck(mu_block_);
	std::vector<std::string> ser_block;
	for (auto &block:blocks_) 
	{
        ser_block.push_back(block.blockheader_.SerializeAsString());
	}
    
    size_t size = ser_block.size();
	std::string blocks;
    for(size_t i = 0; i < size; i++)
    {
        blocks += Str2Hex(ser_block[i]);
        blocks += "_";
    }
    return blocks;
}

bool BlockPoll::VerifyHeight(const CBlock& block)
{
	int db_status = 0;
	auto pRocksDb = MagicSingleton<Rocksdb>::GetInstance();
	Transaction* txn = pRocksDb->TransactionInit();
	if( txn == NULL )
	{
		ERRORLOG("(ReqBlock) TransactionInit failed !");
		return false;
	}

	ON_SCOPE_EXIT{
		pRocksDb->TransactionDelete(txn, false);
	};

	unsigned int ownblockHeight;
	pRocksDb->GetBlockTop(txn, ownblockHeight);

	unsigned int preheight;
	db_status = pRocksDb->GetBlockHeightByBlockHash(txn, block.prevhash(), preheight);
    if (db_status == 0) 
	{
		if(ownblockHeight > (preheight + 5) )
		{
			return false;
		}
    }
	return true;
}













