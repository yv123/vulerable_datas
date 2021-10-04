# -*- coding = utf-8 -*-
# @Time:2021/9/20 16:25
# @Author:yangwei
# @File:create_collection.py
# software:PyCharm

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

    db = client.mongoDB111

    cars = db.cars.find()

    print(cars.next())
    # print(cars.next())
    # print(cars.next())

    # cars.rewind()

    # print(cars.next())
    # print(cars.next())
    # print(cars.next())
    #
    # print(list(cars))