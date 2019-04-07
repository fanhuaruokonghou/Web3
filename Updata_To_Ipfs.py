import ipfsapi

api = ipfsapi.connect('127.0.0.1', 5001)


def upload(path):
    file_addr = api.add(path)
    return file_addr


if __name__ == '__main__':
    upload('I:/磁盘报表.txt')
