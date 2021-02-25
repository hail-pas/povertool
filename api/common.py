"""
核心工具封装
"""
import base64
import hashlib
import hmac
import os

import OpenSSL
import httpx as httpx
import jwt

from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import SHA
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from django.conf import settings
from pyDes import CBC, PAD_PKCS5, des
from OpenSSL import crypto
from OpenSSL.crypto import FILETYPE_PEM
from passlib.context import CryptContext

class AESUtil:
    """
    aes 加密与解密 - 对称
    """

    def __init__(self, key: str, style="pkcs7", mode=AES.MODE_ECB):
        self.mode = mode
        self.style = style
        key = base64.b64decode(key.encode())
        self.aes = AES.new(key, self.mode)

    def encrypt_data(self, data: str):
        data = data.encode()
        pad_data = pad(data, AES.block_size, style=self.style)
        return str(base64.encodebytes(self.aes.encrypt(pad_data)), encoding="utf8").replace(
            "\n", ""
        )

    def decrypt_data(self, data: str):
        data = data.encode()
        pad_data = pad(data, AES.block_size, style=self.style)
        return str(
            unpad(self.aes.decrypt(base64.decodebytes(pad_data)), block_size=AES.block_size).decode(
                "utf8"
            )
        )

    @staticmethod
    def generate_key(length=256) -> str:
        random_key = os.urandom(length)
        private_key = hashlib.sha256(random_key).digest()
        return base64.b64encode(private_key).decode()


class DESUtil:
    """
    DES 加密解密 - 对称
    """

    def __init__(self, key: str, mode=CBC, iv="00000000", padding=None, pad_mode=PAD_PKCS5):
        self.des = des(key, mode, iv, padding, pad_mode)

    def encrypt_data(
        self, data: str,
    ):
        data = data.encode()
        data = self.des.encrypt(data)
        return base64.b64encode(data).decode()

    def decrypt_data(self, data: str):
        decode = base64.b64decode(data)
        decrypt_data = self.des.decrypt(decode)
        return decrypt_data.decode()


class RSAUtil:
    """
    RSA 加密 签名 - 非对称
    """

    def __init__(self, pub_key_path: str, private_key_path: str, password: str):
        self.password = password
        with open(private_key_path, "rb") as f:
            self.private_key = f.read()
        with open(pub_key_path, "rb") as f:
            self.pub_key = f.read()

    def encrypt(self, text: str, length=200) -> str:
        """
        rsa 加密
        """
        key = RSA.import_key(self.pub_key)
        cipher = PKCS1_v1_5.new(key)
        res = []
        for i in range(0, len(text), length):
            text_item = text[i: i + length]
            cipher_text = cipher.encrypt(text_item.encode(encoding="utf-8"))
            res.append(cipher_text)
        return base64.b64encode(b"".join(res)).decode()

    def decrypt(self, text: str):
        """
        rsa 解密
        """
        key = RSA.import_key(self._get_private_key())
        cipher = PKCS1_v1_5.new(key)
        return cipher.decrypt(
            base64.b64decode(text), Random.new().read(15 + SHA.digest_size)
        ).decode()

    def _get_private_key(self,):
        """
        从pfx文件读取私钥
        """
        pfx = crypto.load_pkcs12(self.private_key, self.password.encode())
        res = crypto.dump_privatekey(crypto.FILETYPE_PEM, pfx.get_privatekey())
        return res

    def sign(self, text) -> str:
        """
        rsa 签名
        """
        p12 = OpenSSL.crypto.load_pkcs12(self.private_key, self.password.encode())
        pri_key = p12.get_privatekey()
        return base64.b64encode(OpenSSL.crypto.sign(pri_key, text.encode(), "sha256")).decode()

    def verify(self, sign, data: str):
        """
        验签
        """
        key = OpenSSL.crypto.load_certificate(FILETYPE_PEM, self.pub_key)
        return OpenSSL.crypto.verify(key, base64.b64decode(sign), data.encode(), "sha256")


class HashUtil:
    """
    散列加密
    """
    @staticmethod
    def md5_encode(s: str) -> str:
        """
        md5加密
        """
        m = hashlib.md5(s.encode(encoding="utf-8"))
        return m.hexdigest()

    @staticmethod
    def hmac_sha256_encode(k: str, s: str) -> str:
        """
        hmacsha256加密
        """
        return hmac.digest(k.encode(), s.encode(), hashlib.sha256).hex()

    @staticmethod
    def sha1_encode(s: str) -> str:
        """
        sha1加密
        """
        m = hashlib.sha1(s.encode(encoding="utf-8"))
        return m.hexdigest()


class Password:
    """
    密码加密验证工具
    """

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def verify_password(cls, plain_password, hashed_password):
        return cls.pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def get_password_hash(cls, password):
        return cls.pwd_context.hash(password)

class Jwt:
    """
    json web token 工具
    """

    algorithm = "HS256"

    def __init__(self, secret: str):
        self.secret = secret

    def get_jwt(self, payload: dict) -> bytes:
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def decode(self, credentials) -> dict:
        return jwt.decode(credentials, self.secret, algorithm=self.algorithm)

async def proxy_request(
    method,
    url,
    params=None,
    data=None,
    json=None,
    headers=None,
):
    # 代理请求封装; http://USERNAME:PASSWORD@host:port
    assert method in ["post", "get"]  # nosec:B101
    proxies = {
            "all": settings.PROXY_URL
        }
    async with httpx.AsyncClient(proxies=proxies) as client:
        if method == "get":
            ret = await client.get(url, params=params, headers=headers, timeout=20)
        else:
            ret = await client.post(
                url, params=params, data=data, json=json, headers=headers, timeout=20
            )
    return ret
