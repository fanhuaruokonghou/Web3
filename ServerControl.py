import json
import init
import sys


def get_ip_list():
    ip_list = init.contract_ip_instance.getIp()
    data = {
        'number': ip_list[0],
        'ip': ip_list[1],
        'user': ip_list[2],
        'area': ip_list[3]
    }
    init.contract_data_instance.set_start(transact={'from': init.owner})
    json_data = json.dumps(data)
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
    return json_data


def set_data_length(length):
    init.contract_data_instance.SetLength(length, transact={'from': init.owner})


def set_ip_length(length):
    init.contract_ip_instance.SetLength(length, transact={'from': init.owner})


if __name__ == "__main__":
    if sys.argv[1] == "FileInfoOk":
        get_file_list()
    elif sys.argv[1] == "IpIfOk":
        get_ip_list()
    elif sys.argv[1] == "data_length":
        set_data_length(int(sys.argv[2]))
    elif sys.argv[1] == "ip_length":
        set_ip_length(int(sys.argv[2]))
    else:
        print("参数错误！！")
    # set_data_length(2)
    # set_ip_length(2)
