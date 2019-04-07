# from web3.auto import w3
# import asyncio
#
#
# def handle_event(event):
#     print(event)
#     # and whatever
#
#
# async def log_loop(event_filter, poll_interval):
#     while True:
#         for event in event_filter.get_new_entries():
#             handle_event(event)
#         await asyncio.sleep(poll_interval)
#
#
# def main():
#     block_filter = w3.eth.filter('latest')
#     tx_filter = w3.eth.filter('pending')
#     loop = asyncio.get_event_loop()
#     try:
#         loop.run_until_complete(
#             asyncio.gather(
#                 log_loop(block_filter, 2),
#                 log_loop(tx_filter, 2)))
#     finally:
#         loop.close()
#
#
# if __name__ == '__main__':
#     main()

from web3.auto import w3
from threading import Thread
import time
import asyncio


def handle_event(event):
    print(event)
    # and whatever


async def log_loop(event_filter, poll_interval):
    while True:
        for event in event_filter.get_new_entries():
            handle_event(event)
        time.sleep(poll_interval)


def main():
    loop = asyncio.new_event_loop()
    block_filter = w3.eth.filter('latest')
    worker = Thread(target=log_loop, args=(block_filter, 5), daemon=True)
    worker.start()
        # .. do some other stuff


if __name__ == '__main__':
    main()
