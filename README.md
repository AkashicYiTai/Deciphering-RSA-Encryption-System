# Deciphering-RSA-Encryption-
## 题目  
RSA大礼包  
## 摘要  
利用多种针对RSA的攻击，如RSA共模攻击、pollard、低加密指数法、因数碰撞法、Fermat攻击等，尽可能多得在所截获的数据中，挖掘出原文和参数。  
## 题目描述  
现在有一个RSA加解密软件，并且得到了一些明密文对和对应的参数，而且截获了一些密文。现在利用多种针对RSA的攻击，对明密文对和对应的参数，以及截获的密文进行分析和挖掘。要求从加密数据中，恢复通关密语和RSA的体制参数，以及对应的明文。  
## 过程  
### 1.RSA共模攻击  
#### 原理
生成秘钥的过程中使用了相同的模数n，此时用不同的秘钥e加密同一信息m即：  
c1 = m ^ e1  mod n  
c2 = m ^ e2  mod n  
若两个秘钥e互素根据扩展的欧几里得算法则存在s1，s2有：  
e1 * s1 + e2 * s2 = gcd(e1 , e2) = 1  
结合以上所有信息，可以得到一个结论：  
(c1 ^ s1 * c2 ^ s2) mod n = m  
因此，在不知道秘钥的情况下，得到了m：  
m = (c1 ^ s1 * c2 ^ s2) mod n  
#### 代码
```
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
```
#### 结果  
```
Frame0: My secre
Frame4: My secre
```
### 2.Pollard  
#### 原理
给定：整数n（已知是合数）
目标：找到一个因子d|n
步骤：
固定整数B  
选择一个整数k，k是大部分b的乘积满足b≤B；例如k=B！  
选择一个随机整数a满足2 ≤ a ≤ n - 2  
计算 r = a ^ k mod n  
计算d = gcd(r - 1 , n)  
如果d = 1或者d = n，回到步骤1，否则d就是要找的因子  
#### 代码
```
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
```
#### 结果
```
Frame2: That is
Frame6: "Logic "
Frame19: instein.
```
### 3.低加密指数法  
#### 原理  
假设用户使用的秘钥e = 5，考虑到加密关系满足：  
c ≡ m ^ 5 mod N  
则：  
m ^ 5 = c + k * N  
攻击者可以从小到大枚举k，一次开五次根，知道开出整数为止  
#### 代码
```
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
```
#### 结果
```
Frame3: t is a f
Frame8: t is a f
Frame12: t is a f
Frame16: t is a f
Frame20: t is a f
```
### 4.因数碰撞法  
#### 代码
```
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
```
#### 结果
```
Frame1: . Imagin
Frame18: m A to B
```
### 5.Fermat攻击
#### 原理  
费马攻击基于一个事实：如果RSA的参数p、q相差不大（|p-q| < N^(1/4)）时，可以通过费马分解法比较容易地分解N  
设  
a=1/2(p+q)  
b=1/2(p-q)  
则有  
N=(a+b)*(a-b)=a^2-b^2  
所以我们可以通过遍历a，计算b ^ 2 = N - a ^ 2并判断 b ^ 2 是否为完全平方数来判断是否得到了正确的  a 和 b  
#### 代码
```
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
```
#### 结果  
```
Frame10: will get
```  
### 根据已经破译的明文，猜测所有明文为：  
```
My secret is a famous saying of Albert Einstein. That is "Logic will get you from A to B. Imagination will take you everywhere."
```
## 总结
### 心得  
通过这次大作业，我学习了多种针对RSA的攻击方式，比如RSA共模攻击、pollard、低加密指数法、因数碰撞法、Fermat攻击等，了解了他们的原理，对RSA的结构和缺点有了更深入的了解，数论的知识得到了巩固。这次作业让我认识到，再完美的算法，在实现的过程中，稍有疏忽也会导致漏洞的出现。  
### 问题
对于数论的部分知识，有的地方无法深入理解，在查阅课本和资料后，得到了解决  
## 参考文献
https://blog.csdn.net/qq_31408919/article/details/104917729  
https://blog.csdn.net/weixin_46395886/article/details/114434642  
《信息安全数学基础》  
