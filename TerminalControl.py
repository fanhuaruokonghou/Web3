import init
from web3.auto import w3
import json
from crypto import HDPrivateKey, HDKey


def init(path, password):
    global key_json
    global contract
    global nonce
    global private_key
    file = open(path, "r")
    key_json = json.load(file)
    file.close()
    contract = w3.eth.contract(address=init.config['address_IpControl'], abi=init.config['abi_IpControl'])
    nonce = init.web3.eth.getTransactionCount('0x578bfa5e1809217E495e1E2CaE75a5434b9636b5')
    private_key = w3.eth.account.decrypt(key_json, password)


def set_file_list(number, file_number, data_type, size, user, period, area, file_addr, file_hash, key):
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
    tx = contract.functions.set_ip(
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
        'chainId': 1001,
        'gas': 700000,
        'gasPrice': w3.toWei('2', 'gwei'),
        'nonce': nonce,
    })
    tx = w3.eth.account.signTransaction(tx, private_key=private_key)
    init.web3.eth.sendRawTransaction(tx.rawTransaction)
    return


def set_ip(number, ip, user, area):
    tx = contract.functions.set_ip(
        number,
        ip,
        init.web3.toChecksumAddress(user),
        area
    ).buildTransaction({
        'chainId': 1001,
        'gas': 700000,
        'gasPrice': w3.toWei('2', 'gwei'),
        'nonce': nonce,
    })
    tx = w3.eth.account.signTransaction(tx, private_key=private_key)
    init.web3.eth.sendRawTransaction(tx.rawTransaction)
    return


if __name__ == "__main__":
    # init("‪C:/Users/w/Desktop/key.json", '123456')
    master_key = HDPrivateKey.master_key_from_mnemonic(
        'laundry snap patient survey sleep strategy finger bone real west arch protect', '123456')
    root_keys = HDKey.from_path(master_key, "m/44'/60'/0'")
    acct_priv_key = root_keys[-1]
    for i in range(10):
        keys = HDKey.from_path(acct_priv_key, '{change}/{index}'.format(change=0, index=i))
        private_key = keys[-1]
        public_key = private_key.public_key
        print("Index %s:" % i)
        print("  Private key (hex, compressed): " + private_key._key.to_hex())
        print("  Address: " + private_key.public_key.address())




