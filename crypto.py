import base58
import base64
import hashlib
import hmac
from mnemonic.mnemonic import Mnemonic
import random
from two1.bitcoin.utils import bytes_to_str
from two1.bitcoin.utils import rand_bytes
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

    Args:
        k (int): 私钥.

    Returns:
        PrivateKey: 私钥对象.
    """

    @staticmethod
    def from_b58check(private_key):
        """ 解码Base58Check编码的私钥

        Args:
            private_key (str): 经过Base58Check编码的对象.

        Returns:
            PrivateKey: 私钥对象
        """
        raise NotImplementedError

    def __init__(self, k):
        self.key = k
        self._public_key = None

    @property
    def public_key(self):
        """ 返回该私钥的公钥

        Returns:
            PublicKey:
                与此私钥对应的PublicKey对象。
        """
        return self._public_key

    def to_b58check(self, testnet=False):
        """ 生成此私钥的Base58Check编码.

        Returns:
            str: 表示密钥的Base58Check编码字符串。
        """
        raise NotImplementedError

    def to_hex(self):
        """ 生成序列化密钥的十六进制编码。

        Returns:
           str: 表示密钥的十六进制编码字符串。
        """
        return bytes_to_str(bytes(self))

    def __bytes__(self):
        raise NotImplementedError

    def __int__(self):
        raise NotImplementedError


class PublicKeyBase(object):
    """ PublicKey and HDPublicKey的基类。

    Args:
        x (int): x坐标.
        y (int): y坐标.

    Returns:
        PublicKey: 表示公钥的对象。

    """

    @staticmethod
    def from_bytes(key_bytes):
        """ 从字节（或十六进制）字符串生成公钥对象。

        Args:
            key_bytes (bytes or str): 一个字节流。

        Returns:
            PublicKey: 公钥对象.
        """
        raise NotImplementedError

    @staticmethod
    def from_private_key(private_key):
        """ 根据私钥对象生成公钥对象.

        Args:
            private_key (PrivateKey): 私钥对象

        Returns:
            PublicKey: 公钥对象.
        """
        return private_key.public_key

    def __init__(self):
        pass

    def hash160(self, compressed=True):
        """ 返回公钥的SHA-256哈希的RIPEMD-160哈希。

        Args:
            compressed (bool): 是否应使用压缩密钥。
        Returns:
            bytes: RIPEMD-160字节字符串。
        """
        raise NotImplementedError

    def address(self, compressed=True, testnet=False):
        """ 返回HASH160的Base58Check编码版本的Address属性。

        Args:
            compressed (bool): 是否压缩公钥.
            testnet (bool): 密钥是否用于测试网络。 False表示主网使用情况.

        Returns:
            bytes: Base58Check编码的字符串
        """
        raise NotImplementedError

    def to_hex(self):
        """ 序列化字节流的十六进制表示。

        Returns:
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

        Returns:
            b (bytes): 33字节的字符串.
        """
        raise NotImplementedError


class PrivateKey(PrivateKeyBase):
    """ 封装比特币ECDSA私钥。

    该类提供生成私钥的功能，
    获取相应的公钥和序列化/反序列化为各种格式。

    Args:
        k (int): 私钥.

    Returns:
        PrivateKey: 表示私钥的对象.
    """
    TESTNET_VERSION = 0xEF
    MAINNET_VERSION = 0x80

    @staticmethod
    def from_bytes(b):
        """ 从底层字节生成PrivateKey.

        Args:
            b (bytes): 包含256位（32字节）整数的字节流.

        Returns:
            tuple(PrivateKey, bytes): PrivateKey对象和其余字节。
        """
        if len(b) < 32:
            raise ValueError('b must contain at least 32 bytes')

        return PrivateKey(int.from_bytes(b[:32], 'big'))

    @staticmethod
    def from_hex(h):
        """ 从十六进制编码的字符串生成PrivateKey。

        Args:
            h (str): 包含256位（32字节）整数的十六进制编码字符串。

        Returns:
            PrivateKey: 私钥对象.
        """
        return PrivateKey.from_bytes(bytes.fromhex(h))

    @staticmethod
    def from_int(i):
        """ 从整数初始化私钥.

        Args:
            i (int): 作为私钥的整数。

        Returns:
            PrivateKey: 表示私钥的对象。
        """
        return PrivateKey(i)

    @staticmethod
    def from_b58check(private_key):
        """ 解码Base58Check编码的私钥.

        Args:
            private_key (str):Base58Check编码的私钥.

        Returns:
            PrivateKey: 私钥对象
        """
        b58dec = base58.b58decode_check(private_key)
        version = b58dec[0]
        assert version in [PrivateKey.TESTNET_VERSION,
                           PrivateKey.MAINNET_VERSION]

        return PrivateKey(int.from_bytes(b58dec[1:], 'big'))

    @staticmethod
    def from_random():
        """ 从随机整数初始化私钥。

        Returns:
            PrivateKey: 表示私钥的对象。
        """
        return PrivateKey(random.SystemRandom().randrange(1, bitcoin_curve.n))

    def __init__(self, k):
        self.key = k
        self._public_key = None

    @property
    def public_key(self):
        """ 返回与此私钥关联的公钥。

        Returns:
            PublicKey:
                与此私钥对应的PublicKey对象。
        """
        if self._public_key is None:
            self._public_key = PublicKey.from_point(
                bitcoin_curve.public_key(self.key))
        return self._public_key

    def to_b58check(self, testnet=False):
        """生成此私钥的Base58Check编码。

        Returns:
            str: 表示密钥的Base58Check编码字符串。
        """
        version = self.TESTNET_VERSION if testnet else self.MAINNET_VERSION
        return base58.b58encode_check(bytes([version]) + bytes(self))

    def __bytes__(self):
        return self.key.to_bytes(32, 'big')

    def __int__(self):
        return self.key


class PublicKey(PublicKeyBase):
    """ 封装比特币ECDSA公钥。

    此类为使用ECDSA公钥提供了高级API，特别是用于比特币（secp256k1）。

    Args:
        x (int): x坐标.
        y (int): y坐标.

    Returns:
        PublicKey: 表示公钥的对象.
    """

    TESTNET_VERSION = 0x6F
    MAINNET_VERSION = 0x00

    @staticmethod
    def from_point(p):
        """ 从包含x，y坐标的任何对象生成公钥对象。

        Args:
            p (Point):一个对象，包含secp256k1曲线上某点的二维仿射表示。

        Returns:
            PublicKey: 公钥对象.
        """
        return PublicKey(p.x, p.y)

    @staticmethod
    def from_int(i):
        """ 从整数生成公钥对象。

        Note:
            这假设整数的高32字节是公钥点的x分量，低32字节是y分量。

        Args:
            i (Bignum): 一个512位整数，表示secp256k1曲线上的公钥点.

        Returns:
            PublicKey: 公钥对象.
        """
        point = ECPointAffine.from_int(bitcoin_curve, i)
        return PublicKey.from_point(point)

    @staticmethod
    def from_base64(b64str, testnet=False):
        """ 从Base64编码的字符串生成公钥对象.

        Args:
            b64str (str): Base64编码的字符串.
            testnet (bool) (Optional): 如果为True，则更改密钥前面的版本。

        Returns:
            PublicKey: 公钥对象.
        """
        return PublicKey.from_bytes(base64.b64decode(b64str))

    @staticmethod
    def from_bytes(key_bytes):
        """ 从字节（或十六进制）字符串生成公钥对象。

        字节流必须是SEC种类
        （http://www.secg.org/）：从单个字节开始讲述
        什么关键表示如下。 完整的，未压缩的密钥
        表示为：0x04后跟64个字节
        点的x和y分量。 对于压缩密钥
        对于偶数y分量，0x02后跟32个字节
        包含x组件。 对于带有压缩的密钥
        奇数y分量，0x03后跟32个字节
        x组件。

        Args:
            key_bytes (bytes or str): 符合上述内容的字节流.

        Returns:
            PublicKey: 公钥对象.
        """
        b = get_bytes(key_bytes)
        key_bytes_len = len(b)

        key_type = b[0]
        if key_type == 0x04:
            # Uncompressed
            if key_bytes_len != 65:
                raise ValueError("key_bytes must be exactly 65 bytes long when uncompressed.")

            x = int.from_bytes(b[1:33], 'big')
            y = int.from_bytes(b[33:65], 'big')
        elif key_type == 0x02 or key_type == 0x03:
            if key_bytes_len != 33:
                raise ValueError("key_bytes must be exactly 33 bytes long when compressed.")

            x = int.from_bytes(b[1:33], 'big')
            ys = bitcoin_curve.y_from_x(x)

            # 选择与key_type对应的那个
            last_bit = key_type - 0x2
            for y in ys:
                if y & 0x1 == last_bit:
                    break
        else:
            return None

        return PublicKey(x, y)

    @staticmethod
    def from_hex(h):
        """ 从十六进制编码的字符串生成公钥对象。

        有关十六进制字符串的要求，请参见from_bytes（）。

        Args:
            h (str): 十六进制字符串

        Returns:
            PublicKey: 公钥对象.
        """
        return PublicKey.from_bytes(h)


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

        Args:
            compressed (bool): 是否应该压缩密钥使用。
        Returns:
            bytes: RIPEMD-160字节字符串.
        """
        return self.ripe_compressed if compressed else self.ripe

    def address(self, compressed=True):
        """ 返回HASH160的Base58Check编码版本的Address属性。

        Args:
            compressed (bool): 是否应使用压缩密钥。

        Returns:
            bytes: Base58Check编码的字符串
        """
        return encode_hex(self.keccak[12:])

    def to_base64(self):
        """ 序列化字节流的十六进制表示。

        Returns:
            b (str): Base64编码的字符串.
        """
        return base64.b64encode(bytes(self))

    def __int__(self):
        mask = 2 ** 256 - 1
        return ((self.point.x & mask) << bitcoin_curve.nlen) | (self.point.y & mask)

    def __bytes__(self):
        return bytes(self.point)

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        Returns:
            b (bytes): 一个33字节长的字节字符串。
        """
        return self.point.compressed_bytes


class HDKey(object):
    """ Base class for HDPrivateKey and HDPublicKey.

    Args:
        key (PrivateKey or PublicKey): 用于签名/验证的基础简单私钥或公钥。
        chain_code (bytes): 与HD密钥关联的链代码。
        depth (int): 主密钥低于主节点多少级别。 根据定义，主节点的depth= 0。
        index (int): 介于0和0xffffffff之间的值，表示子编号。 value> = 0x80000000被视为强化子项。
        parent_fingerprint (bytes): 父节点的指纹。 这是主节点的0x00000000。

    Returns:
        HDKey: An HDKey object.
    """
    @staticmethod
    def from_b58check(key):
        """ Decodes a Base58Check encoded key.

        The encoding must conform to the description in:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format

        Args:
            key (str): A Base58Check encoded key.

        Returns:
            HDPrivateKey or HDPublicKey:
                Either an HD private or
                public key object, depending on what was serialized.
        """
        return HDKey.from_bytes(base58.b58decode_check(key))

    @staticmethod
    def from_bytes(b):
        """ 从底层字节生成HDPrivateKey或HDPublicKey。

        Args:
            b (bytes): A byte stream conforming to the above.

        Returns:
            HDPrivateKey or HDPublicKey:
                HD private 还是 public key 对象, 取决于序列化的内容。
        """
        if len(b) < 78:
            raise ValueError("b must be at least 78 bytes long.")

        version = int.from_bytes(b[:4], 'big')
        depth = b[4]
        parent_fingerprint = b[5:9]
        index = int.from_bytes(b[9:13], 'big')
        chain_code = b[13:45]
        key_bytes = b[45:78]

        rv = None
        if version == HDPrivateKey.MAINNET_VERSION or version == HDPrivateKey.TESTNET_VERSION:
            if key_bytes[0] != 0:
                raise ValueError("First byte of private key must be 0x00!")

            private_key = int.from_bytes(key_bytes[1:], 'big')
            rv = HDPrivateKey(key=private_key,
                              chain_code=chain_code,
                              index=index,
                              depth=depth,
                              parent_fingerprint=parent_fingerprint)
        elif version == HDPublicKey.MAINNET_VERSION or version == HDPublicKey.TESTNET_VERSION:
            if key_bytes[0] != 0x02 and key_bytes[0] != 0x03:
                raise ValueError("First byte of public key must be 0x02 or 0x03!")

            public_key = PublicKey.from_bytes(key_bytes)
            rv = HDPublicKey(x=public_key.point.x,
                             y=public_key.point.y,
                             chain_code=chain_code,
                             index=index,
                             depth=depth,
                             parent_fingerprint=parent_fingerprint)
        else:
            raise ValueError("incorrect encoding.")

        return rv

    @staticmethod
    def from_hex(h):
        """ 从底层的十六进制编码字符串生成HDPrivateKey或HDPublicKey。

        The serialization must conform to the description in:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format

        Args:
            h (str): A hex-encoded string conforming to the above.

        Returns:
            HDPrivateKey or HDPublicKey:
                Either an HD private or
                public key object, depending on what was serialized.
        """
        return HDKey.from_bytes(bytes.fromhex(h))

    @staticmethod
    def from_path(root_key, path):
        p = HDKey.parse_path(path)

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

    @staticmethod
    def path_from_indices(l):
        p = []
        for n in l:
            if n == "m":
                p.append(n)
            else:
                if n & 0x80000000:
                    _n = n & 0x7fffffff
                    p.append(str(_n) + "'")
                else:
                    p.append(str(n))

        return "/".join(p)

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

        Returns:
            bool: True if this is a master node, False otherwise.
        """
        return self.depth == 0

    @property
    def hardened(self):
        """ Whether or not this is a hardened node.

        Hardened nodes are those with indices >= 0x80000000.

        Returns:
            bool: True if this is hardened, False otherwise.
        """
        # A hardened key is a key with index >= 2 ** 31, so
        # we check that the MSB of a uint32 is set.
        return self.index & 0x80000000

    @property
    def identifier(self):
        """ 返回键的标识符。

        密钥的标识符和指纹定义为：
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        Returns:
            bytes: 一个20字节的RIPEMD-160哈希。
        """
        raise NotImplementedError

    @property
    def fingerprint(self):
        """ 返回密钥的指纹，它是其标识符的前4个字节。

        密钥的标识符和指纹定义为：
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        Returns:
            bytes: RIPEMD-160哈希的前4个字节。
        """
        return self.identifier[:4]

    def to_b58check(self, testnet=False):
        """ Generates a Base58Check encoding of this key.

        Args:
            testnet (bool): True if the key is to be used with
                testnet, False otherwise.
        Returns:
            str: A Base58Check编码的字符串 representing the key.
        """
        b = self.testnet_bytes if testnet else bytes(self)
        return base58.b58encode_check(b)

    def _serialize(self, testnet=False):
        # 序列化
        version = self.TESTNET_VERSION if testnet else self.MAINNET_VERSION
        key_bytes = self._key.compressed_bytes if isinstance(self, HDPublicKey) else b'\x00' + bytes(self._key)
        return (version.to_bytes(length=4, byteorder='big') +
                bytes([self.depth]) +
                self.parent_fingerprint +
                self.index.to_bytes(length=4, byteorder='big') +
                self.chain_code +
                key_bytes)

    def __bytes__(self):
        return self._serialize()

    @property
    def testnet_bytes(self):
        """ testnet密钥的序列化。

        Returns:
            bytes:
                密钥的78字节序列化，特别是对于testnet（即前2个字节将是0x0435）。
        """
        return self._serialize(True)


class HDPrivateKey(HDKey, PrivateKeyBase):
    """ 根据BIP-0032实现HD私钥：
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    对于绝大多数用例，3个静态函数
    HDPrivateKey.master_key_from_entropy，
    HDPrivateKey.master_key_from_seed和
    将使用HDPrivateKey.from_parent）而不是直接使用
    构建一个对象。

    Args:
        key (PrivateKey or PublicKey): 用于签名/验证的基础简单私钥或公钥。
        chain_code (bytes): 与HD密钥关联的链代码。
        depth (int): 主密钥低于主节点多少级别。 根据定义，主节点的depth= 0。
        index (int): 介于0和0xffffffff之间的值，表示子编号。 value> = 0x80000000被视为强化子项。
        parent_fingerprint (bytes): 父节点的指纹。 这是主节点的0x00000000。

    Returns:
        HDKey: HDKey对象.

    """
    MAINNET_VERSION = 0x0488ADE4
    TESTNET_VERSION = 0x04358394

    @staticmethod
    def master_key_from_mnemonic(mnemonic, passphrase=''):
        """ 从助记符生成主密钥。

        Args:
            mnemonic (str): 表示从中生成主密钥的种子的助记词。
            passphrase (str): 密码如果使用的话。

        Returns:
            HDPrivateKey: 主私钥。
        """
        return HDPrivateKey.master_key_from_seed(
            Mnemonic.to_seed(mnemonic, passphrase))

    @staticmethod
    def master_key_from_entropy(passphrase='', strength=128):
        """ 从系统熵生成主密钥。

        Args:
            strength (int): 所需的熵量。 这应该是128到256之间的32的倍数。
            passphrase (str): 生成的助记符字符串的可选密码。

        Returns:
            HDPrivateKey, str:
                一个由主私钥和一个助记符字符串组成的元组，可以从中恢复种子。
        """
        if strength % 32 != 0:
            raise ValueError("strength must be a multiple of 32")
        if strength < 128 or strength > 256:
            raise ValueError("strength should be >= 128 and <= 256")
        entropy = rand_bytes(strength // 8)
        m = Mnemonic(language='english')
        n = m.to_mnemonic(entropy)
        return HDPrivateKey.master_key_from_seed(
            Mnemonic.to_seed(n, passphrase)), n

    @staticmethod
    def master_key_from_seed(seed):
        """ 从提供的种子生成主密钥。

        Args:
            seed (bytes or str): 一串字节或十六进制字符串

        Returns:
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

        Args:
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
            raise ValueError("index is out of range: 0 <= index <= 2**32 - 1")

        private_key = PrivateKey(key)
        HDKey.__init__(self, private_key, chain_code, index, depth,
                       parent_fingerprint)
        self._public_key = None

    @property
    def public_key(self):
        """ 返回与此私钥关联的公钥。

        Returns:
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

        Returns:
            bytes: 一个20字节的RIPEMD-160哈希。
        """
        return self.public_key.hash160()

    def __int__(self):
        return int(self.key)


class HDPublicKey(HDKey, PublicKeyBase):
    """ 根据BIP-0032实现HD公钥：
    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

     对于绝大多数用例，静态函数将使用HDPublicKey.from_parent（）而不是直接使用
     构建一个对象。

    Args:
        x (int): x 表示公钥的点的组成部分。
        y (int): y 表示公钥的点的组成部分。
        chain_code (bytes): 与HD密钥关联的链代码.
        depth (int):主密钥低于主节点多少级别。 通过定义，主节点的深度= 0。
        index (int): 介于0和0xffffffff之间的值，表示子编号。 值> = 0x80000000被视为强化子项。
        parent_fingerprint (bytes): 父节点的指纹。 这是主节点的0x00000000。

    Returns:
        HDPublicKey: 一个HDPublicKey对象。

    """

    #MAINNET_VERSION = 0x0488B21E
    #TESTNET_VERSION = 0x043587CF

    @staticmethod
    def from_parent(parent_key, i):
        """
        """
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

        Returns:
            bytes: 一个20字节的RIPEMD-160哈希。
        """
        return self.hash160()

    def hash160(self, compressed=True):
        """ 返回非扩展公钥的SHA-256哈希的RIPEMD-160哈希。

        Note:
            这始终返回公钥的压缩版本的哈希值。

        Returns:
            bytes: RIPEMD-160字节字符串。
        """
        return self._key.hash160(True)

    def address(self, compressed=True, testnet=False):
        """ 返回HASH160的Base58Check编码版本的Address属性。

        Args:
            compressed (bool): 是否应该压缩密钥
               be used.
            testnet (bool): 密钥是否用于测试网络。 False表示主网使用情况。

        Returns:
            bytes: Base58Check编码的字符串
        """
        return self._key.address(True)

    @property
    def compressed_bytes(self):
        """ 字节串对应于该公钥的压缩表示。

        Returns:
            b (bytes): 一个33字节长的字节字符串。
        """
        return self._key.compressed_bytes
