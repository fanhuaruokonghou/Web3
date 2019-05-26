import init
from web3.auto import w3
import json
from crypto import HDPrivateKey, HDKey

contract_ip = w3.eth.contract(address=init.config['address_IpControl'], abi=init.config['abi_IpControl'])
contract_file = w3.eth.contract(address=init.config['address_DataControl'], abi=init.config['abi_DataControl'])


# 通过json文件导入私钥
def init_json_private_key(path, password):
    file = open(path, "r")
    key_json = json.load(file)
    file.close()
    private_key = w3.eth.account.decrypt(key_json, password)
    address = w3.eth.account.privateKeyToAccount(private_key).address
    return private_key, address


# 通过助记词导入
def init_mnemonic(mnemonic, index, password):
    master_key = HDPrivateKey.master_key_from_mnemonic(mnemonic, password)
    root_keys = HDKey.from_path(master_key, "m/44'/60'/0'")
    acct_private_key = root_keys[-1]
    for i in range(index):
        keys = HDKey.from_path(acct_private_key, '{change}/{index}'.format(change=0, index=i))
    private_key_mnemonic = keys[-1]
    private_key = private_key_mnemonic._key.to_hex()
    address = private_key_mnemonic.public_key.address()
    return private_key, address


def set_file_list(number, file_number, data_type, size, user, period, area, file_addr, file_hash, key, private_key):
    # number;  //设备唯一标识
    # file_number;  //文件序号
    # data_type;  //数据类型
    # size;  //文件大小
    # user;  //账户
    # period;  //时段
    # area;  //地区
    # file_addr;  //文件索引
    # file_hash;  //文件校验Hash
    # key;  //AES256位密钥
    nonce = init.web3.eth.getTransactionCount(w3.toChecksumAddress(user))
    tx = contract_file.functions.set_file_list(
        number,
        file_number,
        data_type,
        size,
        w3.toChecksumAddress(user),
        period,
        area,
        file_addr,
        file_hash,
        key
    ).buildTransaction({
        'chainId': 10,
        'gas': 700000,
        'gasPrice': w3.toWei('2', 'gwei'),
        'nonce': nonce,
    })
    js = json.dumps(tx, sort_keys=True, indent=4, separators=(',', ':'))
    print('构造的交易:\n' + str(js))
    tx = w3.eth.account.signTransaction(tx, private_key=private_key)
    js = str(tx).replace(",",",\n")
    print('经过签名的交易:\n' + str(js))
    ash = init.web3.eth.sendRawTransaction(tx.rawTransaction)
    print('使用交易hash在区块链上查询到的交易:\n' + str(init.web3.eth.getTransaction(w3.toHex(ash))).replace(",", ",\n"))
    return


def set_ip(number, ip, user, area, private_key):
    nonce = init.web3.eth.getTransactionCount(w3.toChecksumAddress(user))
    tx = contract_ip.functions.set_ip(
        number,
        ip,
        init.web3.toChecksumAddress(user),
        area
    ).buildTransaction({
        'chainId': 10,
        'gas': 700000,
        'gasPrice': w3.toWei('2', 'gwei'),
        'nonce': nonce,
    })
    tx = w3.eth.account.signTransaction(tx, private_key=private_key)
    init.web3.eth.sendRawTransaction(tx.rawTransaction)
    return


if __name__ == "__main__":
    # init_mnemonic('laundry snap patient survey sleep strategy finger bone real west arch protect', 0, '123456')
    key = init_json_private_key(
        "./UTC--2019-03-05T04-26-50.181815333Z--f77918f9bc7af8e58904d1804dc1741b1a753948", "123456")
    set_file_list("1", 0, 1, "90K", key[1], "两小时", "黑龙江", "QmUH2KfFunixc27QjLmd6n4RLsnjeYtuLcwWvSCG4mE9Nc", "1212", "129812", w3.toHex(key[0]))
    # print(key[0])
    # set_ip(1, "2", "0x022a85B6B9fF4d1c13ebbEd975353677642A3328", "3", "0x7976994352843dd20f311072338f78e3f8a3395b41226d9da83755d8264b3141")
    # nonce = init.web3.eth.getTransactionCount(w3.toChecksumAddress(key[1]))
    # print(nonce)