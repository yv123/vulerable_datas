# -*- coding = utf-8 -*-
# @Time:2021/9/23 17:15
# @Author:yangwei
# @File:search__github_patch_url.py
# software:PyCharm
#查询涉及多少个漏洞库，并且有github patch url的库有多少个

from pymongo import MongoClient

cars = [ {'name': 'Audi', 'price': 52642},
    {'name': 'Mercedes', 'price': 57127},
    {'name': 'Skoda', 'price': 9000},
    {'name': 'Volvo', 'price': 29000},
    {'name': 'Bentley', 'price': 350000},
    {'name': 'Citroen', 'price': 21000},
    {'name': 'Hummer', 'price': 41400},
    {'name': 'Volkswagen', 'price': 21600} ]

client = MongoClient('mongodb://localhost:27017/')

with client:
    client = MongoClient('mongodb://localhost:27017/')

    with client:
        db = client.vulnerabledb
        vulnerable_data=db.vulnerable_data.find()
        print(vulnerable_data)
