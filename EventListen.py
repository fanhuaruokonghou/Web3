import asyncio
import init
import json
import time


def handle_event(event):
    t = time.time()
    str_list = str(event)
    str_list1 = str_list[14:-1].replace("'args': AttributeDict({", '')
    str_list1 = str_list1.replace("})", '')
    str_list1 = str_list1.replace("HexBytes(", '')
    str_list1 = str_list1.replace(")", '')
    str_list1 = str_list1.replace("\n", '')
    str_list1 = str_list1.replace("\'", '\"')
    json_list1 = json.loads(str_list1)
    str_list = \
        "{" + "\"event\": \"" + str(json_list1['event']) +\
        "\", \"length\": " + str(json_list1['length']) + \
        "\", \"time\": " + str(int(round(t * 1000))) + "}\n"
    file = open('file_list.txt', mode='a', buffering=-1, encoding='utf-8')
    file.writelines(str_list)
    file.close()


async def log_loop(event_filter, poll_interval):
    while True:
        for event in event_filter.get_new_entries():
            handle_event(event)
        await asyncio.sleep(poll_interval)


def main():
    event_filter = init.contract_ip_instance1.events.IpIfOk.createFilter(
        fromBlock='latest')
    event_filter1 = init.contract_data_instance1.events.FileInfoOk.createFilter(
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
