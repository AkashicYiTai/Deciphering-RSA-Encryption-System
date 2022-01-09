import gmpy2
import binascii
import math


# 欧几里得算法
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


# 公共模数攻击
def same_modulus():
    # 寻找公共模数
    print('公共模数攻击')
    index1 = 0
    index2 = 0
    for i in range(21):
        for j in range(i + 1, 21):
            if ns[i] == ns[j]:
                index1, index2 = i, j
    e1 = int(es[index1], 16)
    e2 = int(es[index2], 16)
    n = int(ns[index1], 16)
    c1 = int(cs[index1], 16)
    c2 = int(cs[index2], 16)
    s = egcd(e1, e2)
    s1 = s[1]
    s2 = s[2]
    # 求模反元素
    if s1 < 0:
        s1 = - s1
        c1 = gmpy2.invert(c1, n)
    elif s2 < 0:
        s2 = - s2
        c2 = gmpy2.invert(c2, n)

    m = pow(c1, s1, n) * pow(c2, s2, n) % n

    # print(m)
    # print(binascii.a2b_hex(hex(m)[2:]))
    result = binascii.a2b_hex(hex(m)[-16:]).decode('ascii')
    print('Frame', index1, ':', result, sep='')
    print('Frame', index2, ':', result, sep='')
    return 0


# 因数碰撞法
def same_factor():
    print('因数碰撞法')
    plaintext = []
    index = []
    for i in range(21):
        for j in range(i + 1, 21):
            if int(ns[i], 16) == int(ns[j], 16):
                continue
            prime = gmpy2.gcd(int(ns[i], 16), int(ns[j], 16))
            if prime != 1:
                index.append(i)
                index.append(j)
                p_of_frame = prime
    q_of_frame1 = int(ns[index[0]], 16) // p_of_frame
    q_of_frame18 = int(ns[index[1]], 16) // p_of_frame

    phi_of_frame1 = (p_of_frame - 1) * (q_of_frame1 - 1)
    phi_of_frame18 = (p_of_frame - 1) * (q_of_frame18 - 1)

    d_of_frame1 = gmpy2.invert(int(es[index[0]], 16), phi_of_frame1)
    d_of_frame18 = gmpy2.invert(int(es[index[1]], 16), phi_of_frame18)

    plaintext_of_frame1 = gmpy2.powmod(int(cs[index[0]], 16), d_of_frame1, int(ns[index[0]], 16))
    plaintext_of_frame18 = gmpy2.powmod(int(cs[index[1]], 16), d_of_frame18, int(ns[index[1]], 16))

    final_plain_of_frame1 = binascii.a2b_hex(hex(plaintext_of_frame1)[-16:]).decode('ascii')
    final_plain_of_frame18 = binascii.a2b_hex(hex(plaintext_of_frame18)[-16:]).decode('ascii')

    print('Frame', index[0], ':', final_plain_of_frame1, sep='')
    print('Frame', index[1], ':', final_plain_of_frame18, sep='')

    return 0


# 低加密指数攻击
# 经过输出检测,发现Frame3,Frame8,Frame12,Frame16,Frame20采用低加密指数e=5进行加密
# 前置函数中国剩余定理
def chinese_remainder_theorem(items):
    N = 1
    for a, n in items:
        N *= n
        result = 0
    for a, n in items:
        m = N // n
        d, r, s = egcd(n, m)
        if d != 1:
            N = N // n
            continue
        result += a * s * m
    return result % N, N


# 低加密指数e == 5


def low_e_5():
    print('低加密指数法')
    sessions = [{"c": int(cs[3], 16), "n": int(ns[3], 16)},
                {"c": int(cs[8], 16), "n": int(ns[8], 16)},
                {"c": int(cs[12], 16), "n": int(ns[12], 16)},
                {"c": int(cs[16], 16), "n": int(ns[16], 16)},
                {"c": int(cs[20], 16), "n": int(ns[20], 16)}]
    data = []
    for session in sessions:
        data = data + [(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开五次方根
    plaintext3_8_12_16_20 = gmpy2.iroot(gmpy2.mpz(x), 5)
    print('Frame3:', binascii.a2b_hex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    print('Frame8:', binascii.a2b_hex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    print('Frame12:', binascii.a2b_hex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    print('Frame16:', binascii.a2b_hex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    print('Frame20:', binascii.a2b_hex(hex(plaintext3_8_12_16_20[0])[-16:]).decode('ascii'), sep='')
    return 0


# 定义费马分解法,适用于p,q相近的情况
# 爆破之后发现Frame10中的模数可以在短时间内使用此方法分解

def pq(n):
    B = math.factorial(2 ** 14)
    u = 0;
    v = 0;
    i = 0
    u0 = gmpy2.iroot(n, 2)[0] + 1
    while (i <= (B - 1)):
        u = (u0 + i) * (u0 + i) - n
        if gmpy2.is_square(u):
            v = gmpy2.isqrt(u)
            break
        i = i + 1
    p = u0 + i + v
    return p


def fermat_resolve():
    for i in range(10, 14):
        N = int(ns[i], 16)
        p = pq(N)


def get_content_of_frame10():
    print('Fermat法')
    p = 9686924917554805418937638872796017160525664579857640590160320300805115443578184985934338583303180178582009591634321755204008394655858254980766008932978699
    n = int(ns[10], 16)
    c = int(cs[10], 16)
    e = int(es[10], 16)
    q = n // p
    phi_of_frame10 = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi_of_frame10)
    m = gmpy2.powmod(c, d, n)
    final_plain = binascii.a2b_hex(hex(m)[-16:]).decode('ascii')
    print('Frame10:', final_plain, sep='')
    return 0


# 定义Pollard p-1分解法,适用于p-1或q-1能够被小素数整除的情况
# 经过爆破发现Frame2,Frame6,Frame19的模数可以使用该方法分解
def pp1(n):
    B = 2 ** 20
    a = 2
    for i in range(2, B + 1):
        a = pow(a, i, n)
        d = gmpy2.gcd(a - 1, n)
        if (d >= 2) and (d <= (n - 1)):
            q = n // d
            n = q * d
    return d


def pollard_resolve():
    print('Pollard法')
    index_list = [2, 6, 19]
    plaintext = []
    for i in range(3):
        N = int(ns[index_list[i]], 16)
        c = int(cs[index_list[i]], 16)
        e = int(es[index_list[i]], 16)
        p = pp1(N)
        q = N // p
        phi_of_frame = (p - 1) * (q - 1)
        d = gmpy2.invert(e, phi_of_frame)
        m = gmpy2.powmod(c, d, N)
        plaintext.append(binascii.a2b_hex(hex(m)[2:]))
        print('Frame', index_list[i], ':', (binascii.a2b_hex(hex(m)[-16:])).decode('ascii'))
    return 0


if __name__ == "__main__":
    ns = []
    cs = []
    es = []
    ps = []
    for i in range(21):
        with open(r"C:\Users\29606\Desktop\Frame\Frame" + str(i), "r") as f:
            tmp = f.read()
            ns.append(tmp[0:256])
            es.append(tmp[256:512])
            cs.append(tmp[512:768])

    same_modulus()
    same_factor()
    low_e_5()
    get_content_of_frame10()
    pollard_resolve()

    print('''
现有的明文为:
Frame0 My secre
Frame1 . Imagin
Frame2  That is 
Frame3 t is a f
Frame4 My secre
Frame5 
Frame6  "Logic 
Frame7 
Frame8 t is a f
Frame9
Frame10 will get
Frame11
Frame12 t is a f
Frame13
Frame14
Frame15
Frame16 t is a f
Frame17
Frame18 m A to B
Frame19 instein.
Frame20 t is a f
    ''')

    final_secret = "My secret is a famous saying of Albert Einstein. That is \"Logic will get you from A to B. Imagination will take you everywhere.\""
print('因此猜测所有的明文为：', final_secret)
