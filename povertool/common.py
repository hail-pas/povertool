"""
核心工具封装
"""
import base64
import datetime
import hashlib
import hmac
import os
import random
import string
import time
from typing import List

import aioredis
import httpx as httpx
import jwt
import OpenSSL
from aioredis import Redis
from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad
from django.conf import settings
from OpenSSL import crypto
from OpenSSL.crypto import FILETYPE_PEM
from passlib.context import CryptContext
from pyDes import CBC, PAD_PKCS5, des

import redis
from redis import WatchError


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
            text_item = text[i : i + length]
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


class AsyncRedisUtil:
    """
    异步redis操作
    """

    r = None  # type:Redis

    @classmethod
    async def init(cls, host="127.0.0.1", port=6379, password=None, db=0, **kwargs):
        cls.r = await aioredis.create_redis_pool(
            f"redis://{host}:{port}", password=password, db=db, **kwargs
        )
        return cls.r

    @classmethod
    async def _exp_of_none(cls, *args, exp_of_none, callback):
        if not exp_of_none:
            return await getattr(cls.r, callback)(*args)
        key = args[0]
        tr = cls.r.multi_exec()
        fun = getattr(tr, callback)
        exists = await cls.r.exists(key)
        if not exists:
            fun(*args)
            tr.expire(key, exp_of_none)
            ret, _ = await tr.execute()
        else:
            fun(*args)
            ret = (await tr.execute())[0]
        return ret

    @classmethod
    async def set(cls, key, value, exp=None):
        assert cls.r, "must call init first"
        await cls.r.set(key, value, expire=exp)

    @classmethod
    async def get(cls, key, default=None):
        assert cls.r, "must call init first"
        value = await cls.r.get(key)
        if value is None:
            return default
        return value

    @classmethod
    async def hget(cls, name, key, default=0):
        """
        缓存清除，接收list or str
        """
        assert cls.r, "must call init first"
        v = await cls.r.hget(name, key)
        if v is None:
            return default
        return v

    @classmethod
    async def get_or_set(cls, key, default=None, value_fun=None):
        """
        获取或者设置缓存
        """
        assert cls.r, "must call init first"
        value = await cls.r.get(key)
        if value is None and default:
            return default
        if value is not None:
            return value
        if value_fun:
            value, exp = await value_fun()
            await cls.r.set(key, value, expire=exp)
        return value

    @classmethod
    async def delete(cls, key):
        """
        缓存清除，接收list or str
        """
        assert cls.r, "must call init first"
        return await cls.r.delete(key)

    @classmethod
    async def sadd(cls, name, values, exp_of_none=None):
        assert cls.r, "must call init first"
        return await cls._exp_of_none(name, values, exp_of_none=exp_of_none, callback="sadd")

    @classmethod
    async def hset(cls, name, key, value, exp_of_none=None):
        assert cls.r, "must call init first"
        return await cls._exp_of_none(name, key, value, exp_of_none=exp_of_none, callback="hset")

    @classmethod
    async def hincrby(cls, name, key, value=1, exp_of_none=None):
        assert cls.r, "must call init first"
        return await cls._exp_of_none(name, key, value, exp_of_none=exp_of_none, callback="hincrby")

    @classmethod
    async def hincrbyfloat(cls, name, key, value, exp_of_none=None):
        assert cls.r, "must call init first"
        return await cls._exp_of_none(
            name, key, value, exp_of_none=exp_of_none, callback="hincrbyfloat"
        )

    @classmethod
    async def incrby(cls, name, value=1, exp_of_none=None):
        assert cls.r, "must call init first"
        return await cls._exp_of_none(name, value, exp_of_none=exp_of_none, callback="incrby")

    @classmethod
    async def close(cls):
        cls.r.close()
        await cls.r.wait_closed()


class RedisUtil:
    """
    同步redis
    """

    r = None

    @classmethod
    def init(cls, conn=None, host="127.0.0.1", port=6379, password="", db=0, **kwargs):
        if conn:
            cls.r = conn
        else:
            pool = redis.ConnectionPool(host=host, port=port, password=password, db=db, **kwargs)
            cls.r = redis.Redis(connection_pool=pool)

    @classmethod
    def _exp_of_none(cls, *args, exp_of_none, callback):
        if not exp_of_none:
            return getattr(cls.r, callback)(*args)
        with cls.r.pipeline() as pipe:
            count = 0
            while True:
                try:
                    fun = getattr(pipe, callback)
                    key = args[0]
                    pipe.watch(key)
                    exp = pipe.ttl(key)
                    pipe.multi()
                    if exp == -2:
                        fun(*args)
                        pipe.expire(key, exp_of_none)
                        ret, _ = pipe.execute()
                    else:
                        fun(*args)
                        ret = pipe.execute()[0]
                    return ret
                except WatchError:
                    if count > 3:
                        raise WatchError
                    count += 1
                    continue

    @classmethod
    def get_or_set(cls, key, default=None, value_fun=None):
        """
        获取或者设置缓存
        """
        value = cls.r.get(key)
        if value is None and default:
            return default
        if value is not None:
            return value
        if value_fun:
            value, exp = value_fun()
            cls.r.set(key, value, exp)
        return value

    @classmethod
    def get(cls, key, default=None):
        value = cls.r.get(key)
        if value is None:
            return default
        return value

    @classmethod
    def set(cls, key, value, exp=None):
        """
        设置缓存
        """
        return cls.r.set(key, value, exp)

    @classmethod
    def delete(cls, key):
        """
        缓存清除，接收list or str
        """
        return cls.r.delete(key)

    @classmethod
    def sadd(cls, name, values, exp_of_none=None):
        return cls._exp_of_none(name, values, exp_of_none=exp_of_none, callback="sadd")

    @classmethod
    def hset(cls, name, key, value, exp_of_none=None):
        return cls._exp_of_none(name, key, value, exp_of_none=exp_of_none, callback="hset")

    @classmethod
    def hincrby(cls, name, key, value=1, exp_of_none=None):
        return cls._exp_of_none(name, key, value, exp_of_none=exp_of_none, callback="hincrby")

    @classmethod
    def hincrbyfloat(cls, name, key, value, exp_of_none=None):
        return cls._exp_of_none(name, key, value, exp_of_none=exp_of_none, callback="hincrbyfloat")

    @classmethod
    def incrby(cls, name, value=1, exp_of_none=None):
        return cls._exp_of_none(name, value, exp_of_none=exp_of_none, callback="incrby")

    @classmethod
    def hget(cls, name, key, default=0):
        """
        缓存清除，接收list or str
        """
        v = cls.r.hget(name, key)
        if v is None:
            return default
        return v


# tool functions


async def proxy_request(
    method: str,
    url: str,
    params: dict = None,
    data: dict = None,
    json: dict = None,
    headers: dict = None,
):
    # 代理请求封装; http://USERNAME:PASSWORD@host:port
    assert method in ["post", "get"]  # nosec:B101
    proxies = {"all": settings.PROXY_URL}
    async with httpx.AsyncClient(proxies=proxies) as client:
        if method == "get":
            ret = await client.get(url, params=params, headers=headers, timeout=20)
        else:
            ret = await client.post(
                url, params=params, data=data, json=json, headers=headers, timeout=20
            )
    return ret


def datetime_now(d: int = 0, h: int = 0, m: int = 0):
    """
    时间加减获取
    """
    tmp = datetime.datetime.now()
    if d:
        tmp += datetime.timedelta(days=d)
    if h:
        tmp += datetime.timedelta(hours=h)
    if m:
        tmp += datetime.timedelta(minutes=m)
    return tmp


def datetime2timestamp(dt: datetime):
    """
    时间转时间戳
    """
    return int(time.mktime(dt.timetuple()))


def rest_seconds(mode: str) -> int:
    """
    获取剩余秒数
    """
    assert mode in ["month", "week", "day"], "mode must be one of month,week,year"
    if mode == "day":
        return datetime2timestamp(datetime_now(d=1).date()) - datetime2timestamp(datetime_now())
    if mode == "week":
        now = datetime_now()
        offset = 7 - now.weekday()
        weekend = now.date() + datetime.timedelta(days=offset)
        return datetime2timestamp(weekend) - datetime2timestamp(now)
    if mode == "month":
        now = datetime_now()
        next_month = now.date().replace(day=28) + datetime.timedelta(days=4)
        return datetime2timestamp(
            next_month - datetime.timedelta(days=next_month.day - 1)
        ) - datetime2timestamp(now)


def get_range_date(mode):
    """
    获取当前时间的范围区间边界
    :param mode: month,week,day
    :return:
    """
    assert mode in ["month", "week", "day"], "mode must be one of month,week,year"
    now = datetime.datetime.now()
    if mode == "day":
        zero_today = now - datetime.timedelta(
            hours=now.hour, minutes=now.minute, seconds=now.second, microseconds=now.microsecond
        )
        last_today = zero_today + datetime.timedelta(hours=23, minutes=59, seconds=59)
        return zero_today, last_today
    elif mode == "week":
        zero_week = now - datetime.timedelta(
            days=now.weekday(),
            hours=now.hour,
            minutes=now.minute,
            seconds=now.second,
            microseconds=now.microsecond,
        )
        last_week = zero_week + datetime.timedelta(days=6, hours=23, minutes=59, seconds=59)

        return zero_week, last_week
    elif mode == "month":
        zero_month = datetime.datetime(now.year, now.month, 1)
        last_month = (
            datetime.datetime(now.year, now.month + 1, 1)
            - datetime.timedelta(days=1)
            + datetime.timedelta(hours=23, minutes=59, seconds=59)
        )
        return zero_month, last_month


def generate_random_string(length: int, all_digits: bool = False, excludes: List = None):
    """
    生成任意长度字符串
    """
    if excludes is None:
        exclude = []
    if all_digits:
        all_char = string.digits
    else:
        all_char = string.ascii_letters + string.digits
    if excludes:
        for char in excludes:
            all_char.replace(char, "")
    return "".join(random.sample(all_char, length))


def join_params(
    params: dict,
    key: str = None,
    filter_none: bool = True,
    exclude_keys: List = None,
    sep: str = "&",
    reverse: bool = False,
    key_alias: str = "key",
):
    """
    字典排序拼接参数
    """
    tmp = []
    for p in sorted(params, reverse=reverse):
        value = params[p]
        if filter_none and value in [None, ""]:
            continue
        if exclude_keys:
            if p in exclude_keys:
                continue
        tmp.append("{0}={1}".format(p, value))
    if key:
        tmp.append("{0}={1}".format(key_alias, key))
    ret = sep.join(tmp)
    return ret


def get_client_ip(request):
    """
    获取客户端真实ip
    :param request:
    :return:
    """
    if request.META.get("HTTP_X_FORWARDED_FOR"):
        ip = request.META["HTTP_X_FORWARDED_FOR"]
    else:
        ip = request.META["REMOTE_ADDR"]
    return ip.split(",")[0]
