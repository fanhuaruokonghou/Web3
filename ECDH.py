import collections
import random


EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # 素数
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # 参数 y**2 = x**3 + a * x + b
    a=0,
    b=7,
    # 基点
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # 基点的阶
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # 协因子
    h=1,
)


# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """返回k mod p的倒数。
     此函数返回唯一的整数x，使得（x * k）％p == 1。
     k必须是非零，p必须是素数。
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """如果给定点位于椭圆曲线上，则返回True."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # 两点关于x轴对称  之和为无穷远点
        return None

    if x1 == x2:
        # 两点重合
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """返回k * point"""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


def make_keypair():
    """生成私钥"""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)
    return private_key, public_key


# Keypair generation and ECDHE ################################################
# 生成公私钥对
def back_key():
    private_key, public_key = make_keypair()
    private_key = hex(private_key)
    public_key = '04' + hex(public_key[0])[2:] + hex(public_key[1])[2:]
    return private_key, public_key


# 获取共同秘密
def get_secret(private_key, public_key):
    if public_key[0:2] == '04':
        public_key = (int(public_key[2:66], 16), int(public_key[66:], 16))
        return scalar_mult(int(private_key, 16), public_key)
    else:
        return '公钥格式错误'


if __name__ == '__main__':
    # print('Curve:', curve.name)
    #
    # # Alice generates her own keypair.
    # alice_private_key, alice_public_key = \
    #     make_keypair(int('0x880f21dd86691d4ffcbdc8097959b1eafe95f906ea73f7e3bda5b7c851e023a7', 16))
    # print("Alice's private key:", hex(alice_private_key))
    # print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public_key))
    #
    # # Bob generates his own key pair.
    # bob_private_key, bob_public_key = \
    #     make_keypair(int('0x77315fe58ddd21b61dff54a89995fdb4ee19148e3f8a61d87017ce3d686b15eb', 16))
    # print("Bob's private key:", hex(bob_private_key))
    # print("Bob's public key: (0x{:x}, 0x{:x})".format(*bob_public_key))
    #
    # # Alice and Bob exchange their public keys and calculate the shared secret.
    # s1 = scalar_mult(alice_private_key, bob_public_key)
    # s2 = scalar_mult(bob_private_key, alice_public_key)
    # print(s1)
    # print(int('0xa9e1886d6dd04b127073e1d89f3d1d5b7629db3299eebe5cd97860a8788692ee', 16))
    # assert s1 == s2
    print(get_secret('0x2b6b02c47784bdef65368391f5e979e6492540260fae33d76bdb0b38396e5325', '04140ec2f9e95424126fef5cacf8501b1da5c24af2c8b1913640bd4159e19a1f89f1be1cd4d2becbff4f6077e9bda7a69a71b65e364c3e2c7d94e6dad4c822ffaa'))