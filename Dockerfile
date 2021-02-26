FROM python:3.8
RUN mkdir -p /usr/share/nginx/povertool
# 修改pip源
RUN mkdir ~/.pip
RUN echo "[global]\nindex-url = https://mirrors.aliyun.com/pypi/simple/\nformat = columns" > ~/.pip/pip.conf

WORKDIR /usr/share/nginx/povertool/

# 安装依赖
COPY pyproject.toml poetry.lock /usr/share/nginx/povertool/
# RUN pip install -r requirements.txt
ENV POETRY_VIRTUALENVS_CREATE=false
RUN pip install poetry
RUN poetry install

# 复制源文件
COPY . /usr/share/nginx/povertool
RUN mkdir ./static