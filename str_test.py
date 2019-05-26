# import json
# from web3 import Web3, HTTPProvider
# from web3.contract import ConciseContract
# # import TerminalControl
#
# file = open("./config/contract.json", "r")
# contract_abi = json.load(file)
# file.close()
#
# file = open("./config/contract_addr.json", "r")
# contract_addr = json.load(file)
# file.close()
#
#
# config = {
#     "abi_DataControl": contract_abi,
#     "address_DataControl": contract_addr,
# }
#
# web3 = Web3(HTTPProvider('http://127.0.0.1:7545'))
# owner = web3.eth.accounts[0]
# contract_data_instance = web3.eth.contract(
#     address=config['address_DataControl'], abi=config['abi_DataControl'], ContractFactoryClass=ConciseContract)
# contract_data_instance1 = web3.eth.contract(
#     address=config['address_DataControl'], abi=config['abi_DataControl'])
#
#
# def test():
#     print(owner)
#     # contract_data_instance.recharge(transact={'from': owner, 'value': 10000000000000000})
#     contract_data_instance.buyRealTimeData("1", "1", 1, 1, 1, transact={'from': owner})
#     print(contract_data_instance.balanceOf(owner))
#
#
# def test1():
#     contract_data_instance.buyData(
#         web3.toChecksumAddress(0x499973Da87eF296F5dF933141E1f60775FcEA0f6), [1, 12], "1", 1, 1, 1, transact={'from': owner})
#
# # def main():
# #     # contract_data_instance.buy(transact={'from': web3.eth.accounts[1], 'value': web3.toWei(10, 'ether')})
# #     # contract_data_instance.sell(100, transact={'from': web3.eth.accounts[1]})
# #     # transact = {'from': web3.toChecksumAddress(0x499973Da87eF296F5dF933141E1f60775FcEA0f6),
# #     #             'value': 10}
# #     contract_data_instance.setPrices(1, 1, transact={'from': owner})
# #     print(contract_data_instance.balanceOf(web3.toChecksumAddress(0x499973Da87eF296F5dF933141E1f60775FcEA0f6)))
# #     # print(web3.eth.getTransactionCount(web3.toChecksumAddress(0x499973Da87eF296F5dF933141E1f60775FcEA0f6)))
# #     # print(web3.eth.getCode('0x5c7029728aa4ca90A6820baf602e91c5c4FB3560'))
# #     # print(web3.eth.getCode('0x499973Da87eF296F5dF933141E1f60775FcEA0f6'))
#
#
# if __name__ == "__main__":
#     # TerminalControl.init_mnemonic('laundry snap patient survey sleep strategy finger bone real west arch protect', 0, '123456')
#     # TerminalControl.p()
#     # test()
#     test1()


from crypto import HDPrivateKey, HDKey

mnemonic = "physical toy explain december juice say hour media assault kidney shine abstract"
password = "123456"
master_key = HDPrivateKey.master_key_from_mnemonic(mnemonic, password)
root_keys = HDKey.from_path(master_key, "m/44'/60'/0'/0")
for x in range(len(root_keys)):
    print(root_keys[x]._key.to_hex())
acct_private_key = root_keys[-1]
index = 20
# i = 19
for i in range(index):
    keys = HDKey.from_path(acct_private_key, '{index}'.format(index=i))
    private_key_mnemonic = keys[-1]
    private_key = private_key_mnemonic._key.to_hex()
    address = private_key_mnemonic.public_key.address()
    print("private--{index}: ".format(index=i) + private_key)
    print("public--{index}: ".format(index=i) + hex(int.from_bytes(private_key_mnemonic.public_key.compressed_bytes, 'big')))
    print("address--{index}: ".format(index=i) + address)
# keys = HDKey.from_path(acct_private_key, '{change}/{index}'.format(change=0, index=i))
# print(len(keys))
# for i in range(len(keys)):
#     private_key_mnemonic = keys[i]
#     private_key = private_key_mnemonic._key.to_hex()
#     address = private_key_mnemonic.public_key.address()
#     print("private--{index}: ".format(index=i) + private_key)
#     print("public--{index}: ".format(index=i) + private_key_mnemonic.public_key().compressed_bytes())
#     print("address--{index}: ".format(index=i) + address)

# keys = HDKey.from_path(acct_private_key, '{change}/{index}'.format(change=0, index=i))
# print(len(keys))
# private_key_mnemonic = keys[0]
# private_key = private_key_mnemonic._key.to_hex()
# address = private_key_mnemonic.public_key.address()
# print("private--{index}: ".format(index=i) + private_key)
# # print("public--{index}: ".format(index=i) + private_key_mnemonic.public_key().compressed_bytes())
# print("address--{index}: ".format(index=i) + address)