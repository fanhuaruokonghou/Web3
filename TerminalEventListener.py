import asyncio
import str_test
import json


def handle_event(event):
    str_list = str(event)
    str_list1 = str_list[14:-1].replace("'args': AttributeDict({", '')
    str_list1 = str_list1.replace("})", '')
    str_list1 = str_list1.replace("HexBytes(", '')
    str_list1 = str_list1.replace(")", '')
    str_list1 = str_list1.replace("\n", '')
    str_list1 = str_list1.replace("\'", '\"')
    json_list1 = json.loads(str_list1)
    # if json_list1['event'] == 'addTx':
    #     print(json_list1)
    # else:
    #     # li = list(json_list1['fileNUmberList'])
    # print(li[1])
    print(json_list1)


async def log_loop(event_filter, poll_interval):
    while True:
        for event in event_filter.get_new_entries():
            handle_event(event)
        await asyncio.sleep(poll_interval)


def main():
    event_filter = str_test.contract_data_instance1.events.addRealTimeTx.createFilter(
        fromBlock='latest')
    event_filter1 = str_test.contract_data_instance1.events.addTx.createFilter(
        fromBlock='latest', argument_filters={'arg1': 10})
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            asyncio.gather(
                log_loop(event_filter, 2),
                log_loop(event_filter1, 2)))
    finally:
        loop.close()


if __name__ == '__main__':
    main()
