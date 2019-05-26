import hashlib
import hmac
from mnemonic.mnemonic import Mnemonic
from two1.bitcoin.utils import bytes_to_str
from two1.crypto.ecdsa import ECPointAffine
from two1.crypto.ecdsa import secp256k1
from eth_utils import encode_hex
from Crypto.Hash import keccak

bitcoin_curve = secp256k1()
sha3_256 = lambda x: keccak.new(digest_bits=256, data=x)


def sha3(seed):
    return sha3_256(seed).digest()


def get_bytes(s):
    """返回十六进制或字节字符串的字节表示形式"""
    if isinstance(s, bytes):
        b = s
    elif isinstance(s, str):
        b = bytes.fromhex(s)
    else:
        raise TypeError("s must be 'bytes' or 'str'!")

    return b


class PrivateKeyBase(object):
    """  PrivateKey 和 HDPrivateKey的基础类

    参数:
        k (int): 私钥.

    返回值:
        PrivateKey: 私钥对象.
    """

    def __init__(self, k):
        self.key = k
        self._public_key = None

    @property
    def public_key(self):
        """ 返回该私钥的公钥

        返回值:
            PublicKey:
                与此私钥对应的PublicKey对象。
        """
        return self._public_key

    def to_hex(self):
        """ 生成序列化密钥的十六进制编码。

        返回值:
           str: 表示密钥的十六进制编码字符串。
        """
        return bytes_to_str(bytes(self))

    def __bytes__(self):
        raise NotImplementedError

    def __int__(self):
        raise NotImplementedError


class PublicKeyBase(object):
    """ PublicKey and HDPublicKey的基类。

    参数:
        x (int): x坐标.
        y (int): y坐标.

    返回值:
        PublicKey: 表示公钥的对象。

    """

    @staticmethod
    def from_bytes(key_bytes):
        """ 从字节（或十六进制）字符串生成公钥对象。

        参数:
            key_bytes (bytes or str): 一个字节流。

        返回值:
            PublicKey: 公钥对象.
        """
        raise NotImplementedError

    @staticmethod
    def from_private_key(private_key):
        """ 根据私钥对象生成公钥对象.

        参数:
            private_key (PrivateKey): 私钥对象

        返回值:
            PublicKey: 公钥对象.
        """
        return private_key.public_key

    def __init__(self):
        pass

    def hash160(self, compressed=True):
        """ 返回公钥的SHA-256哈希的RIPEMD-160哈希。

        参数:
            compressed (bool): 是否应使用压缩密钥。
        返回值:
            bytes: RIPEMD-160字节字符串。
        """
        raise NotImplementedError

    def address(self, compressed=True, testnet=False):
        """ 返回HASH160的Base58Check编码版本的Address属性。

        参数:
            compressed (bool): 是否压缩公钥.
            testnet (bool): 密钥是否用于测试网络。 False表示主网使用情况.

        返回值:
            bytes: Base58Check编码的字符串
        """
        raise NotImplementedError

    def to_hex(self):
        """ 序列化字节流的十六进制表示。

        返回值:
            h (str): 十六进制字符串.
        """
        return bytes_to_str(bytes(self))

    def __bytes__(self):
        raise NotImplementedError

    def __int__(self):
        raise NotImplementedError

    @property
    def compressed_bytes(self):
        """ 字节串对应于该公钥的压缩表示。

        返回值:
            b (bytes): 33字节的字符串.
        """
        raise NotImplementedError


class PrivateKey(PrivateKeyBase):
    """ 封装比特币ECDSA私钥。

    该类提供生成私钥的功能，
    获取相应的公钥和序列化/反序列化为各种格式。

    参数:
        k (int): 私钥.

    返回值:
        PrivateKey: 表示私钥的对象.
    """

    def __init__(self, k):
        self.key = k
        self._public_key = None

    @property
    def public_key(self):
        """ 返回与此私钥关联的公钥。

        返回值:
            PublicKey:
                与此私钥对应的PublicKey对象。
        """
        if self._public_key is None:
            self._public_key = PublicKey.from_point(
                bitcoin_curve.public_key(self.key))
        return self._public_key

    def __bytes__(self):
        return self.key.to_bytes(32, 'big')

    def __int__(self):
        return self.key


class PublicKey(PublicKeyBase):
    """ 封装比特币ECDSA公钥。

    此类为使用ECDSA公钥提供了高级API，特别是用于比特币（secp256k1）。

    参数:
        x (int): x坐标.
        y (int): y坐标.

    返回值:
        PublicKey: 表示公钥的对象.
    """

    @staticmethod
    def from_point(p):
        """ 从包含x，y坐标的任何对象生成公钥对象。

        参数:
            p (Point):一个对象，包含secp256k1曲线上某点的二维仿射表示。

        返回值:
            PublicKey: 公钥对象.
        """
        return PublicKey(p.x, p.y)

    def __init__(self, x, y):
        p = ECPointAffine(bitcoin_curve, x, y)
        if not bitcoin_curve.is_on_curve(p):
            raise ValueError("The provided (x, y) are not on the secp256k1 curve.")

        self.point = p

        # RIPEMD-160 of SHA-256
        r = hashlib.new('ripemd160')
        r.update(hashlib.sha256(bytes(self)).digest())
        self.ripe = r.digest()

        r = hashlib.new('ripemd160')
        r.update(hashlib.sha256(self.compressed_bytes).digest())
        self.ripe_compressed = r.digest()

        self.keccak = sha3(bytes(self)[1:])

    def hash160(self, compressed=True):
        """ 返回公钥的SHA-256哈希的RIPEMD-160哈希。

        参数:
            compressed (bool): 是否应该压缩密钥使用。
        返回值:
            bytes: RIPEMD-160字节字符串.
        """
        return self.ripe_compressed if compressed else self.ripe

    def address(self, compressed=True):
        """ 返回HASH160的Base58Check编码版本的Address属性。

        参数:
            compressed (bool): 是否应使用压缩密钥。

        返回值:
            bytes: Base58Check编码的字符串
        """
        return encode_hex(self.keccak[12:])

    def __int__(self):
        mask = 2 ** 256 - 1
        return ((self.point.x & mask) << bitcoin_curve.nlen) | (self.point.y & mask)

    def __bytes__(self):
        return bytes(self.point)

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        返回值:
            b (bytes): 一个33字节长的字节字符串。
        """
        return self.point.compressed_bytes


class HDKey(object):
    """ Base class for HDPrivateKey and HDPublicKey.

    参数:
        key (PrivateKey or PublicKey): 用于签名/验证的基础简单私钥或公钥。
        chain_code (bytes): 与HD密钥关联的链代码。
        depth (int): 主密钥低于主节点多少级别。 根据定义，主节点的depth= 0。
        index (int): 介于0和0xffffffff之间的值，表示子编号。 value> = 0x80000000被视为强化子项。
        parent_fingerprint (bytes): 父节点的指纹。 这是主节点的0x00000000。

    返回值:
        HDKey: An HDKey object.
    """

    @staticmethod
    def from_path(root_key, path):
        p = HDKey.parse_path(path)
        print(p)
        if p[0] == "m":
            if root_key.master:
                p = p[1:]
            else:
                raise ValueError("root_key must be a master key if 'm' is the first element of the path.")

        keys = [root_key]
        for i in p:
            if isinstance(i, str):
                hardened = i[-1] == "'"
                index = int(i[:-1], 0) | 0x80000000 if hardened else int(i, 0)
            else:
                index = i
            k = keys[-1]
            klass = k.__class__
            keys.append(klass.from_parent(k, index))
        print(len(keys))
        return keys

    @staticmethod
    def parse_path(path):
        if isinstance(path, str):
            # 删除结尾的 "/"
            p = path.rstrip("/").split("/")
        elif isinstance(path, bytes):
            p = path.decode('utf-8').rstrip("/").split("/")
        else:
            p = list(path)
        return p

    def __init__(self, key, chain_code, index, depth, parent_fingerprint):
        if index < 0 or index > 0xffffffff:
            raise ValueError("index is out of range: 0 <= index <= 2**32 - 1")

        if not isinstance(chain_code, bytes):
            raise TypeError("chain_code must be bytes")

        self._key = key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index

        self.parent_fingerprint = get_bytes(parent_fingerprint)

    @property
    def master(self):
        """ 判断是否是主节点。

        返回值:
            bool: True if this is a master node, False otherwise.
        """
        return self.depth == 0

    @property
    def hardened(self):
        """ 这是否是一个强化节点。强化节点是索引 >= 0x80000000的节点。

        返回值:
            bool: True if this is hardened, False otherwise.
        """
        return self.index & 0x80000000

    @property
    def identifier(self):
        """ 返回键的标识符。

        返回值:
            bytes: 一个20字节的RIPEMD-160哈希。
        """
        raise NotImplementedError

    @property
    def fingerprint(self):
        """ 返回密钥的指纹，它是其标识符的前4个字节。

        密钥的标识符和指纹定义为：
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        返回值:
            bytes: RIPEMD-160哈希的前4个字节。
        """
        return self.identifier[:4]

    @property
    def testnet_bytes(self):
        """ testnet密钥的序列化。

        返回值:
            bytes:
                密钥的78字节序列化，特别是对于testnet（即前2个字节将是0x0435）。
        """
        return self._serialize(True)


class HDPrivateKey(HDKey, PrivateKeyBase):

    @staticmethod
    def master_key_from_mnemonic(mnemonic, passphrase=''):
        """ 从助记符生成主密钥。

        参数:
            mnemonic (str): 表示从中生成主密钥的种子的助记词。
            passphrase (str): 密码如果使用的话。

        返回值:
            HDPrivateKey: 主私钥。
        """
        return HDPrivateKey.master_key_from_seed(
            Mnemonic.to_seed(mnemonic, passphrase))

    @staticmethod
    def master_key_from_seed(seed):
        """ 从提供的种子生成主密钥。

        参数:
            seed (bytes or str): 一串字节或十六进制字符串

        返回值:
            HDPrivateKey: 主私钥。
        """
        S = get_bytes(seed)
        I = hmac.new(b"Bitcoin seed", S, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]
        parse_Il = int.from_bytes(Il, 'big')
        if parse_Il == 0 or parse_Il >= bitcoin_curve.n:
            raise ValueError("Bad seed, resulting in invalid key!")

        return HDPrivateKey(key=parse_Il, chain_code=Ir, index=0, depth=0)

    @staticmethod
    def from_parent(parent_key, i):
        """ 从父私钥中派生子私钥。 无法从公共父密钥派生子私钥。

        参数:
            parent_private_key (HDPrivateKey):
        """
        if not isinstance(parent_key, HDPrivateKey):
            raise TypeError("parent_key must be an HDPrivateKey object.")

        hmac_key = parent_key.chain_code
        if i & 0x80000000:
            hmac_data = b'\x00' + bytes(parent_key._key) + i.to_bytes(length=4, byteorder='big')
        else:
            hmac_data = parent_key.public_key.compressed_bytes + i.to_bytes(length=4, byteorder='big')

        I = hmac.new(hmac_key, hmac_data, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]

        parse_Il = int.from_bytes(Il, 'big')
        if parse_Il >= bitcoin_curve.n:
            return None

        child_key = (parse_Il + parent_key._key.key) % bitcoin_curve.n

        if child_key == 0:
            # Incredibly unlucky choice
            return None

        child_depth = parent_key.depth + 1
        return HDPrivateKey(key=child_key,
                            chain_code=Ir,
                            index=i,
                            depth=child_depth,
                            parent_fingerprint=parent_key.fingerprint)

    def __init__(self, key, chain_code, index, depth,
                 parent_fingerprint=b'\x00\x00\x00\x00'):
        if index < 0 or index > 0xffffffff:
            raise ValueError("index is out of range: 0  <= index <= 2**32 -1")

        private_key = PrivateKey(key)
        HDKey.__init__(self, private_key, chain_code, index, depth,
                       parent_fingerprint)
        self._public_key = None

    @property
    def public_key(self):
        """ 返回与此私钥关联的公钥。

        返回值:
            HDPublicKey:
                与此私钥对应的HDPublicKey对象。
        """
        if self._public_key is None:
            self._public_key = HDPublicKey(x=self._key.public_key.point.x,
                                           y=self._key.public_key.point.y,
                                           chain_code=self.chain_code,
                                           index=self.index,
                                           depth=self.depth,
                                           parent_fingerprint=self.parent_fingerprint)

        return self._public_key

    @property
    def identifier(self):
        """ 返回键的标识符。

        密钥的标识符和指纹定义为：
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        在这种情况下，它将返回相应公钥的RIPEMD-160哈希值。

        返回值:
            bytes: 一个20字节的RIPEMD-160哈希。
        """
        return self.public_key.hash160()

    def __int__(self):
        return int(self.key)


class HDPublicKey(HDKey, PublicKeyBase):
    """
    参数:
        x (int): x 表示公钥的点的组成部分。
        y (int): y 表示公钥的点的组成部分。
        chain_code (bytes): 与HD密钥关联的链代码.
        depth (int):主密钥低于主节点多少级别。 通过定义，主节点的深度= 0。
        index (int): 介于0和0xffffffff之间的值，表示子编号。 值> = 0x80000000被视为强化子项。
        parent_fingerprint (bytes): 父节点的指纹。 这是主节点的0x00000000。

    返回值:
        HDPublicKey: 一个HDPublicKey对象。

    """

    @staticmethod
    def from_parent(parent_key, i):

        if isinstance(parent_key, HDPrivateKey):
            # Get child private key
            return HDPrivateKey.from_parent(parent_key, i).public_key
        elif isinstance(parent_key, HDPublicKey):
            if i & 0x80000000:
                raise ValueError("Can't generate a hardened child key from a parent public key.")
            else:
                I = hmac.new(parent_key.chain_code,
                             parent_key.compressed_bytes + i.to_bytes(length=4, byteorder='big'),
                             hashlib.sha512).digest()
                Il, Ir = I[:32], I[32:]
                parse_Il = int.from_bytes(Il, 'big')
                if parse_Il >= bitcoin_curve.n:
                    return None

                temp_priv_key = PrivateKey(parse_Il)
                Ki = temp_priv_key.public_key.point + parent_key._key.point
                if Ki.infinity:
                    return None

                child_depth = parent_key.depth + 1
                return HDPublicKey(x=Ki.x,
                                   y=Ki.y,
                                   chain_code=Ir,
                                   index=i,
                                   depth=child_depth,
                                   parent_fingerprint=parent_key.fingerprint)
        else:
            raise TypeError("parent_key must be either a HDPrivateKey or HDPublicKey object")

    def __init__(self, x, y, chain_code, index, depth,
                 parent_fingerprint=b'\x00\x00\x00\x00'):
        key = PublicKey(x, y)
        HDKey.__init__(self, key, chain_code, index, depth, parent_fingerprint)
        PublicKeyBase.__init__(self)

    @property
    def identifier(self):
        """ 返回键的标识符。

        密钥的标识符和指纹定义为：
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        在这种情况下，它将返回的RIPEMD-160哈希值非扩展公钥。

        返回值:
            bytes: 一个20字节的RIPEMD-160哈希。
        """
        return self.hash160()

    def hash160(self, compressed=True):
        """ 返回非扩展公钥的SHA-256哈希的RIPEMD-160哈希。

        Note:
            这始终返回公钥的压缩版本的哈希值。

        返回值:
            bytes: RIPEMD-160字节字符串。
        """
        return self._key.hash160(True)

    def address(self, compressed=True, testnet=False):
        """ 返回HASH160的Base58Check编码版本的Address属性。

        参数:
            compressed (bool): 是否应该压缩密钥
            testnet (bool): 密钥是否用于测试网络。 False表示主网使用情况。

        返回值:
            bytes: Base58Check编码的字符串
        """
        return self._key.address(True)

    @property
    def compressed_bytes(self):
        """ 字节串对应于该公钥的压缩表示。

        返回值:
            b (bytes): 一个33字节长的字节字符串。
        """
        return self._key.compressed_bytes
