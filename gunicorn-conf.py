# coding=utf-8

import os
import django
# 把标准库中的thread/socket等给替换掉
from gevent import monkey
monkey.patch_all()

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'povertool.settings')
django.setup()

from django.conf import settings
debug = settings.DEBUG
# //绑定与Nginx通信的端口
bind = '0.0.0.0:8000'
daemon = False

worker_class = 'gevent'  # 默认为阻塞模式，最好选择gevent模式,默认的是sync模式
# 日志级别
# debug:调试级别，记录的信息最多；
# info:普通级别；
# warning:警告消息；
# error:错误消息；
# critical:严重错误消息；
loglevel = 'debug'
# 访问日志路径
accesslog = '-'    # 表示标准输出
# 错误日志路径
errorlog = '-'
# 设置gunicorn访问日志格式，错误日志无法设置
access_log_format = '%(t)s %(p)s %(h)s "%(r)s" %(s)s %(L)s %(b)s %(f)s" "%(a)s"'

# 最大请求数之和重启worker，防止内存泄漏
max_requests = 4096
# 随机重启防止所有worker一起重启：randint(0, max_requests_jitter)
max_requests_jitter = 512

# 执行命令
# gunicorn -c gconfig.py main:app
# gunicorn -c gconfig.py main:app -k uvicorn.workers.UvicornWorker