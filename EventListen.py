from web3 import Web3, HTTPProvider
import time
import init

config = {
    "abi_DataControl": init.data_control_abi,
    "address_DataControl": init.data_contract_addr,

    "abi_IpControl": init.ip_control_abi,
    "address_IpControl": init.ip_contract_addr
}


def handle_event(event_filter1):
    print(event_filter1.get_new_entries())


def log_loop(event_filter, poll_interval, event_filter1):
    while True:
        for event in event_filter.get_all_entries():
            handle_event(event, event_filter1)
        time.sleep(poll_interval)


def main():
    # block_filter = web3.eth.filter({"address": "0x9321E4D79E9c05DBB130bf0B54c8E9C24D42Dc12"})
    event_filter1 = contract_instance.events.FileInfoOk.createFilter(fromBlock='latest', argument_filters={'arg1': 10})
    event_filter1.get_new_entries()


if __name__ == "__main__":
    main()
