import json
from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract
# import TerminalControl

file = open("./config/contract.json", "r")
contract_abi = json.load(file)
file.close()

file = open("./config/contract_addr.json", "r")
contract_addr = json.load(file)
file.close()


config = {
    "abi_DataControl": contract_abi,
    "address_DataControl": contract_addr,
}

web3 = Web3(HTTPProvider('http://127.0.0.1:7545'))
owner = web3.eth.accounts[0]
contract_data_instance = web3.eth.contract(
    address=config['address_DataControl'], abi=config['abi_DataControl'], ContractFactoryClass=ConciseContract)
contract_data_instance1 = web3.eth.contract(
    address=config['address_DataControl'], abi=config['abi_DataControl'])


def test():
    print(owner)
    # contract_data_instance.recharge(transact={'from': owner, 'value': 10000000000000000})
    contract_data_instance.buyRealTimeData("1", "1", 1, 1, 1, transact={'from': owner})
    print(contract_data_instance.balanceOf(owner))


def test1():
    contract_data_instance.buyData(
        web3.toChecksumAddress(0x499973Da87eF296F5dF933141E1f60775FcEA0f6), [1, 12], "1", 1, 1, 1, transact={'from': owner})

# def main():
#     # contract_data_instance.buy(transact={'from': web3.eth.accounts[1], 'value': web3.toWei(10, 'ether')})
#     # contract_data_instance.sell(100, transact={'from': web3.eth.accounts[1]})
#     # transact = {'from': web3.toChecksumAddress(0x499973Da87eF296F5dF933141E1f60775FcEA0f6),
#     #             'value': 10}
#     contract_data_instance.setPrices(1, 1, transact={'from': owner})
#     print(contract_data_instance.balanceOf(web3.toChecksumAddress(0x499973Da87eF296F5dF933141E1f60775FcEA0f6)))
#     # print(web3.eth.getTransactionCount(web3.toChecksumAddress(0x499973Da87eF296F5dF933141E1f60775FcEA0f6)))
#     # print(web3.eth.getCode('0x5c7029728aa4ca90A6820baf602e91c5c4FB3560'))
#     # print(web3.eth.getCode('0x499973Da87eF296F5dF933141E1f60775FcEA0f6'))


if __name__ == "__main__":
    # TerminalControl.init_mnemonic('laundry snap patient survey sleep strategy finger bone real west arch protect', 0, '123456')
    # TerminalControl.p()
    # test()
    test1()
