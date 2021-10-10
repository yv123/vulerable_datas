# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
from itemadapter import ItemAdapter
# from scrapy.conf import settings
import pymongo

class TutorialPipeline:
    def __init__(self):
        # 连接数据库
        self.client = pymongo.MongoClient('mongodb://localhost:27017/')
        # 创建库
        self.db = self.client['vulnerabledb222']
        # 创建表
        self.table = self.db['vulnerabledb_datas222']
        self.count=0
    def process_item(self, item, spider):
        self.count=self.count+1
        print(item)
        self.table.update({'identifiers':item['identifiers']}, {'$set': dict(item)},True)
        # self.table.find({}, {"glsa_id": 1, _id: 0}).sort({"likes": -1})
        return item
