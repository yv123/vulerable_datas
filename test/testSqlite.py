# -*- coding = utf-8 -*-
# @Time:2021/9/16 16:57
# @Author:yangwei
# @File:testSqlite.py
# software:PyCharm

import sqlite3
conn=sqlite3.connect('test.db')#打开或者创建文件
print('open database successfully')
c=conn.cursor()
sql='''
    create table company3
    (id int primary key not null,
    name text not null,
    age int not null,
    adress char(50),
    salary real);
'''
c.execute(sql)#执行sql语句
conn.commit()#提交数据库操作
conn.close()#关闭数据库链接
print('成功建表')


