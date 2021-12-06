# -*- coding = utf-8 -*-
# @Time:2021/12/2 14:28
# @Author:yangwei
# @File:read_write_csv.py
# software:PyCharm
import csv

import glob
csv_list = glob.glob('../csv_list/*.csv')
# print('共有%s个CSV文件'% len(csv_list))
# print (csv_list)
from packaging.version import parse as parse_version
from pymongo import MongoClient
client = MongoClient('mongodb://localhost:27017/')
#gentoo
gentoodb = client.vulnerabledb_new_1119
# gentoo_datas=gentoodb.vulnerabledb_datas_new__1119.find()
# f = csv.reader(open('../csv_list/orig_yarp-middleware_ldd.txt_sub.csv','r'))
count=0
# csv_file='../csv_list/orig_urh_ldd.txt_sub.csv'
for csv_file in csv_list:
    csvreader = csv.reader(open(csv_file, "r"))
    current_file=csv_file.split("\\")[-1]
    count+=1
    data=[]
    print(count)
    for i in csvreader:
        i.insert(0,count)
        i.insert(1,current_file)
        for li in i[4:19]:
            if (li != 'NULL'):
                lib_arr = li.split('     ')
                lib_name=lib_arr[1].split('_')[0]
                lib_version=lib_arr[1].split('_')[1]
                gentoo_datas = gentoodb.vulnerabledb_datas_new__1119.find()
                for gentoo_li in gentoo_datas:
                    if(gentoo_li['vulnerable_library']==lib_name):
                        if(parse_version(lib_version) < parse_version(gentoo_li['affected_versions'].split('<')[-1])):
                            cve_relation={}
                            cve_relation['cve']=gentoo_li['identifiers'][0]['value']
                            cve_relation['from']=li
                            cve_relation['lib_name']=gentoo_li['vulnerable_library']
                            cve_relation['affected_versions']=gentoo_li['affected_versions']
                            cve_relation['cwe']=gentoo_li['cwes']
                            cve_relation['cvss']=gentoo_li['cvss']['CVSSVersion3']
                            cve_relation['source']=gentoo_li['identifiers'][1]['value']
                            #塞入到 当前行
                            if(i not in data):
                                if(cve_relation not in i):
                                    i.append(cve_relation)
                                    data.append(i)
                            else:
                                for data_li1 in data:
                                    if(data_li1 == i):
                                        if (cve_relation not in data_li1):
                                            i.append(cve_relation)
                                            data_li1=i
    for data_li in data:
        f = open('../aaa/1.csv',mode='a',encoding='utf-8')
        csv_writer = csv.writer(f)
        print('{{{')
        print(data_li)
        print(']]]')
        csv_writer.writerow(data_li)