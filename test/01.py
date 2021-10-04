# -*- coding = utf-8 -*-
# @Time:2021/9/15 19:57
# @Author:yangwei
# @File:01.py
# software:PyCharm
from bs4 import BeautifulSoup
file=open('./baidu.html','rb')
html=file.read()
bs=BeautifulSoup(html,'html.parser');
print(bs.head)
# 文档搜索
