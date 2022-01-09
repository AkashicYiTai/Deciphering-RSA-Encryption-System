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
def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

# 公共模数攻击
def same_modulus():
    # 寻找公共模数
    index1 = 0
    index2 = 0
    for i in range(21):
        for j in range(i+1, 21):
            if ns[i] == ns[j]:
                print('Same modulus found!' + str((ns[i], ns[j])))
                index1 ,index2 = i, j  
    e1 = int(es[index1], 16)
    e2 = int(es[index2], 16)
    n = int(ns[index1], 16)
    c1 = int(cs[index1], 16)
    c2 = int(cs[index2], 16)
    s = egcd(e1, e2)
    s1 = s[1]
    s2 = s[2]
    # 求模反元素
    if s1<0:
        s1 = - s1
        c1 = gmpy2.invert(c1, n)
    elif s2<0:
        s2 = - s2
        c2 = gmpy2.invert(c2, n)

    m = pow(c1,s1,n)*pow(c2,s2,n) % n

    print(m)
    print(binascii.a2b_hex(hex(m)[2:]))
    result = binascii.a2b_hex(hex(m)[2:])
    return result

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
def pp1(n):
    B=2**20
    a=2
    for i in range(2,B+1):
        a=pow(a,i,n)
        d=gmpy2.gcd(a-1,n)
        if (d>=2)and(d<=(n-1)):
            q=n//d
            n=q*d
    return d
def pollard_resolve():
    index_list = [2,6,19]
    plaintext = []
    for i in range(3):
        N = int(ns[index_list[i]], 16)
        c = int(cs[index_list[i]], 16)
        e = int(es[index_list[i]], 16)
        p = pp1(N)
        print("p of "+ str(index_list[i]) + " is : " + str(p))
        q = N // p
        phi_of_frame = (p-1)*(q-1)
        d = gmpy2.invert(e, phi_of_frame)
        m = gmpy2.powmod(c, d, N)
        plaintext.append(binascii.a2b_hex(hex(m)[2:]))
    return plaintext
```
#### 结果
```
Frame2: That is
Frame6: "Logic "
Frame19: instein.
```
