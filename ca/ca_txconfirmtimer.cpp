#include "ca_txconfirmtimer.h"
#include <iostream>
#include <cassert>
#include "../utils/singleton.h"
#include "../utils/time_util.h"
#include "MagicSingleton.h"
#include "ca_txfailurecache.h"
#include "ca_txconfirmtimer.h"
#include "ca_blockpool.h"
#include "../include/logging.h"

const int TxConfirmation::DEFAULT_CONFIRM_TOTAL = 100;
bool TxConfirmation::is_confirm_ok()
{
    static const float SUCCESS_FACTOR = 0.60;
    const int MIN_CONFIRM_COUNT = (int)(total * SUCCESS_FACTOR);
    return ((count + failed_count) >= MIN_CONFIRM_COUNT);
}

bool TxConfirmation::is_success()
{
    static const float SUCCESS_FACTOR = 0.60;
    return get_success_rate() >= SUCCESS_FACTOR;
}

float TxConfirmation::get_success_rate()
{
    int sum_count = count + failed_count;
    if (sum_count <= 0)
    {
        return 0.0;
    }

    float f_success_count = (float)count;
    float f_sum_count = (float)sum_count;
    return (f_success_count / f_sum_count);
}

int TxConfirmation::get_success_count()
{
    return count;
}


TransactionConfirmTimer::TransactionConfirmTimer()
{
    tx_confirmation_.reserve(128);
}

bool TransactionConfirmTimer::is_confirm_ok(const string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);
    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            return txconfirm.is_confirm_ok();
        }
    }
    return false;
}

bool TransactionConfirmTimer::is_success(const string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);
    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            return txconfirm.is_success();
        }
    }
    return false;
}

float TransactionConfirmTimer::get_success_rate(const string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);
    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            return txconfirm.get_success_rate();
        }
    }
    return 0.0;
}

void TransactionConfirmTimer::add(TxVinCache::Tx& tx, int total/* = TxConfirmation::DEFAULT_CONFIRM_TOTAL*/)
{
    TxConfirmation confirmation;
    confirmation.tx = tx;
    confirmation.startstamp = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
    confirmation.count = 0;
    confirmation.total = total;

    std::lock_guard<std::mutex> lck(mutex_);
    tx_confirmation_.push_back(confirmation);
}

void TransactionConfirmTimer::add(const string& tx_hash, int total/* = TxConfirmation::DEFAULT_CONFIRM_TOTAL*/)
{
    TxVinCache::Tx tx;
    tx.txHash = tx_hash;
    add(tx, total);
}

bool TransactionConfirmTimer::remove(const string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto iter = tx_confirmation_.begin(); iter != tx_confirmation_.end(); ++iter)
    {
        if (iter->tx.txHash == tx_hash)
        {
            tx_confirmation_.erase(iter);
            return true;
        }
    }
    return false;
}

int TransactionConfirmTimer::get_count(const string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            return txconfirm.count;
        }
    }

    return 0;
}

void TransactionConfirmTimer::update_count(const string& tx_hash, CBlock& block)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            ++txconfirm.count;
            txconfirm.block = block;
            break;
        }
    }
}

int TransactionConfirmTimer::get_failed_count(const string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            return txconfirm.failed_count;
        }
    }

    return 0;
}

void TransactionConfirmTimer::update_failed_count(const string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            ++txconfirm.failed_count;
            break;
        }
    }
}

void TransactionConfirmTimer::confirm()
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto iter = tx_confirmation_.begin(); iter != tx_confirmation_.end();)
    {
        uint64_t nowTime = Singleton<TimeUtil>::get_instance()->getlocalTimestamp();
        static const uint64_t CONFIRM_WAIT_TIME = 1000000UL * 6UL;
        if ((nowTime - iter->startstamp) >= CONFIRM_WAIT_TIME)
        {
            //static const int MIN_CONFIRM_COUNT = 60;
            //if (iter->count >= MIN_CONFIRM_COUNT)
            if (iter->is_success())
            {
                MagicSingleton<BlockPoll>::GetInstance()->Add(Block(iter->block));
            }
            else
            {
                MagicSingleton<TxFailureCache>::GetInstance()->Add(iter->tx);
            }
            DEBUGLOG("Handle confirm: iter->count:{}, hash:{}", iter->count, iter->tx.txHash);

            iter = tx_confirmation_.erase(iter);
        }
        else
        {
            ++iter;
        }
    }
}

void TransactionConfirmTimer::timer_start()
{
    this->timer_.AsyncLoop(1000 * 2, TransactionConfirmTimer::timer_process, this);
}

void TransactionConfirmTimer::timer_process(TransactionConfirmTimer* timer)
{
    assert(timer != nullptr);
    
    timer->confirm();
}

void TransactionConfirmTimer::update_id(const string& tx_hash,std::string&id)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            txconfirm.ids.push_back(id);
            break;
        }
    }
}


void TransactionConfirmTimer::get_ids(const string& tx_hash,std::vector<std::string>&ids)
 {
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
           ids = txconfirm.ids;
           break;
        }
    }
 }

 bool TransactionConfirmTimer::is_not_exist_id(const string& tx_hash, const string& id)
 {
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.txHash == tx_hash)
        {
            auto iter = std::find(txconfirm.ids.begin(), txconfirm.ids.end(), id);
            return (iter == txconfirm.ids.end());
        }
    }

    return true;
 }