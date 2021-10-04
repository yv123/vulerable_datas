# -*- coding = utf-8 -*-
# @Time:2021/9/23 17:15
# @Author:yangwei
# @File:search__github_patch_url.py
# software:PyCharm
#查询涉及多少个漏洞库，并且有github patch url的库有多少个

from pymongo import MongoClient
import json
from bson import ObjectId

client=''
def select_data():
    with client:
        db = client.vulnerabledb111
        vulnerable_data=db.vulnerabledb_datas.find()
        hhhhh=[]
        count=0

        for a in (vulnerable_data):
            del a['_id']
            if(len(a['identifiers'])!=0):
                for identifiers_item in a['identifiers']:
                    if(len(identifiers_item['fixed_versions_and_patch'])!=0):
                        if(len(identifiers_item['fixed_versions_and_patch'])!=0):
                            # print(identifiers_item['fixed_versions_and_patch'])
                            # hhhhh.append(a)
                            for identifiers_item_fixed_versions_and_patch_item in identifiers_item['fixed_versions_and_patch']:
                                if(identifiers_item_fixed_versions_and_patch_item!={}):
                                        if(a not in hhhhh):
                                            # print(a)
                                            # con_dbs(a)
                                            hhhhh.append(a)
        print(len(hhhhh))
def vuler_sort():
    with client:
        db = client.vulnerabledb111
        datas=db.vulnerabledb_datas.find().sort([('glsa_id',-1)])
        print(datas)
        for item in datas:
            print(item)
            client.vulner_sort_db.vulner_datas.update_one({'glsa_id': item['glsa_id']}, {'$set': dict(item)}, True)
            # client.vulner_sort_db.vulner_datas.insert_one(dict(item))
        print('完成')
def con_dbs(list):
    with client:
        db = client.github_patch_url_db
        db.github_patch_url_date.insert_one(list)
    print('插入成功')
if __name__=="__main__":
    client = MongoClient('mongodb://localhost:27017/')
    select_data()
    # vuler_sort()