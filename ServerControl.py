import json
import init


def get_ip_list():
    ip_list = init.init.contract_ip_instance.getIp()
    data = {
        'number': ip_list[0],
        'ip': ip_list[1],
        'user': ip_list[2]
    }
    init.contract_data_instance.set_start(transact={'from': init.owner})
    json_data = json.dumps(data)
    print(ip_list)
    print(json_data)
    return json_data


def get_file_list():
    file_list = init.contract_data_instance.get0_1()
    file_list.extend(init.contract_data_instance.get2_3())
    file_list.extend(init.contract_data_instance.get4_5())
    file_list.extend(init.contract_data_instance.get6_7())
    file_list.extend(init.contract_data_instance.get8_9())
    init.contract_data_instance.set_start(transact={'from': init.owner})
    data = {
        'number': file_list[0],
        'file_number': file_list[1],
        'data_type': file_list[2],
        'size': file_list[3],
        'user': file_list[4],
        'period': file_list[5],
        'area': file_list[6],
        'file_addr': file_list[7],
        'file_hash': file_list[8],
        'key': file_list[9]
    }
    json_data = json.dumps(data)
    print(file_list)
    print(json_data)

    return json_data


def ip_list():
    # init.contract_ip_instance.SetLength(2, transact={'from': init.owner})
    # print(init.contract_ip_instance.set_ip(1, TerminalControl.get_host_ip(),
    #                                   web3.toChecksumAddress(init.owner), transact={'from': init.owner}))
    get_ip_list()


def data_list():
    init.contract_data_instance.SetLength(2, transact={'from': init.owner})
    # print(init.contract_data_instance.set_file_list(
    #     1, 1, 1, 1, web3.toChecksumAddress(init.owner),
    #     "1", "1", "1", 1, 1, transact={'from': init.owner}))
    # print(init.contract_data_instance.getLength())
    # r = web3.eventFilter('FileInfoOk', {'fromBlock', 1, 'toBlock', 'latest'})
    # r = init.contract_data_instance.events.FileInfoOk.createFilter(fromBlock=1)
    # print(r)
    # init.contract_data_instance.eth.Eth.getFilterChanges
    # if r:
    #     print(init.contract_data_instance.Get1_2())
    # print(web3.contract.ContractEvents.getLog())
    # print(web3.eth.filter('latest'))
    # print(web3.eth.getFilterLogs(web3.eth.filter().filter_id))
    # print(web3.eth.filter('latest').get_new_entries())
    # print(web3.eth.filter('pending').get_new_entries())
    # print(web3.eth.filter('latest').filter_id)
    # print(web3.eth.filter({"address": "0x9321E4D79E9c05DBB130bf0B54c8E9C24D42Dc12"}).get_all_entries())
    # print(w3.eth.Eth.Filter.filter_id)
    # print(web3.eth.filter({'fromBlock': 1, 'toBlock': 29, 'address': '0xaB2f585274106A2dd1C3Efc77766A47126e1F5D6'}))
    # event_filter = init.contract_data_instance.events.FileInfoOk.createFilter(fromBlock='latest', argument_filters={'arg1': 10})
    # print(event_filter.get_new_entries())
    # print(init.contract_data_instance.Get1_2())
    # get_file_list()
    # get_ip_list()
    # # # print(data_control_abi)

    # init.contract_data_instance.set_start(transact={'from': init.owner})
    # print(init.contract_data_instance.getstart())


if __name__ == "__main__":
    ip_list()
