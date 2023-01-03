#ifndef _CA_TRANS_UTILS_
#define _CA_TRANS_UTILS_

#include "../proto/transaction.pb.h"
#include <string>

struct UtxoTx
{
    int height;
    CTransaction utxo;
};
namespace TransUtils
{
    //根据地址查询与地址相关的质押交易
    bool GetPledgeUtxoByAddr(const std::string &address, std::vector<UtxoTx> &out);
    //根据地址查询与地址相关的解质押交易
    bool GetRedeemUtxoByAddr(const std::string &address, std::vector<UtxoTx> &out);
    //根据地址查询与地址相关的质押与解质押
    bool GetPledgeAndRedeemUtxoByAddr(const std::string &address, std::vector<UtxoTx> &out);
    //根据地址查询与地址相关的正常交易
    bool GetTxUtxoByAddr(const std::string &address, std::vector<UtxoTx> &out);
    //根据地址查询与地址相关的签名交易
    bool GetSignUtxoByAddr(const std::string &address, std::vector<UtxoTx> &out);
    //根据地址查询与地址相关的挖矿交易
    bool GetAwardUtxoByAddr(const std::string &address, std::vector<UtxoTx> &out);
    //根据地址查询与地址相关的质押与解质押以及正常交易
    bool GetUtxoByAddr(const std::string &address, std::vector<UtxoTx> &out);
    //根据地址查询与地址相关的所有交易
    bool GetAllUtxoByAddr(const std::string &address, std::vector<UtxoTx> &out);
}
#endif