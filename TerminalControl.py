from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract
import socket
import init

# config = {
#     "abi_DataControl": init.data_control_abi,
#     "address_DataControl": init.data_contract_addr,
#
#     "abi_IpControl": init.ip_control_abi,
#     "address_IpControl": init.ip_contract_addr
# }
#
# web3 = Web3(HTTPProvider('http://47.102.203.221:8545'))
# owner = web3.eth.accounts[0]
# contract_file_list = web3.eth.contract(
#     address=config['address_DataControl'], abi=config['abi_DataControl'], ContractFactoryClass=ConciseContract)
# contract_ip_list = web3.eth.contract(
#     address=config['address_IpControl'], abi=config['abi_IpControl'], ContractFactoryClass=ConciseContract)


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
    transact_hash = \
        init.contract_data_instance.set_file_list(
            number, file_number, data_type, size, init.web3.toChecksumAddress(user), period, area,
            file_addr, file_hash, key, transact={'from': init.web3.toChecksumAddress(user)})
    return transact_hash


def set_ip(number, user):
    transact_hash = \
        init.contract_ip_instance.set_ip(
            number, get_host_ip(), init.web3.toChecksumAddress(user),
            transact={'from': init.web3.toChecksumAddress(user)})
    return transact_hash


def get_host_ip():
    # 优雅地获取本机IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


if __name__ == "__main__":
    # print(get_host_ip())
    transact_hash_data = set_file_list(1, 1, 1, 1, 0xf77918f9bc7af8e58904d1804dc1741b1a753948, "1", "1", "1", 1, 1)
    transaction = init.web3.eth.getTransaction(transact_hash_data)
    print(init.contract_data_instance1.decode_function_input(transaction.input))

    transact_hash_ip = set_ip(1, 0xf77918f9bc7af8e58904d1804dc1741b1a753948)
    transaction = init.web3.eth.getTransaction(transact_hash_ip)
    print(init.contract_ip_instance1.decode_function_input(transaction.input))


