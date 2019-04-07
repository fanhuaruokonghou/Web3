import json
from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract

file = open("./config/data_control_abi.json", "r")
data_control_abi = json.load(file)
file.close()

file = open("./config/data_contract_addr.json", "r")
data_contract_addr = json.load(file)
file.close()

file = open("./config/ip_control_abi.json", "r")
ip_control_abi = json.load(file)
file.close()

file = open("./config/ip_contract_addr.json", "r")
ip_contract_addr = json.load(file)
file.close()



config = {
    "abi_DataControl": data_control_abi,
    "address_DataControl": data_contract_addr,

    "abi_IpControl": ip_control_abi,
    "address_IpControl": ip_contract_addr
}

web3 = Web3(HTTPProvider('http://127.0.0.1:7545'))
owner = web3.eth.accounts[0]
contract_data_instance = web3.eth.contract(
    address=config['address_DataControl'], abi=config['abi_DataControl'], ContractFactoryClass=ConciseContract)
contract_ip_instance = web3.eth.contract(
    address=config['address_IpControl'], abi=config['abi_IpControl'], ContractFactoryClass=ConciseContract)