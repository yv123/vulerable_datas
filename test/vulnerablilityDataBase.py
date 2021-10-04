# -*-  codeing = utf-8 -*-
# @Time : 2021/9/20 19:47
# @Author : yangwei
# @File :vulnerablilityDataBase.py
# @software :PyCharm
#链接数据库
import time
count=0
from pymongo import MongoClient
#获取列表
import urllib.request
from bs4 import BeautifulSoup
headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36'}
client = ''
#获取首页列表的所有
def ask_glsa_list():
    url='https://glsa.gentoo.org/glsa'
    req=urllib.request.Request(url,None,headers)
    res=urllib.request.urlopen(req,timeout=5)
    html=res.read()
    #解析html文件
    soup=BeautifulSoup(html,"html.parser")
    glsa_list=soup.select('body > div > div > div > div.table-responsive.mb-3 > table   tr')
    vulnerable_library=soup.select('body > div > div > div > div > table  tr > td')
    dataList=[]
    #81条再试试
    for item in glsa_list[253:300]:
        glsa_id=item.select('th a')[0].text
        vulnerable_library=item.select('td')[0].text.split(':')[0]
        print(glsa_id)
        info=get_glsa_package_detail_info(glsa_id)
        obj = {
            'glsa_id': glsa_id,
            'identifiers':info[0],
            'vulnerable_versions':info[1],
            'vulnerable_library':vulnerable_library,
            'programe_language_of_source_code':'',
            'programe_language_of_library':''
        }
        dataList.append(obj)
        print(obj)
        global count
        count+=1
        print(count)
        con_dbs(obj)
    print(dataList)
    print('all over!!!')

def get_glsa_package_detail_info(id):
    url='https://glsa.gentoo.org/glsa/'+id
    req = urllib.request.Request(url, None, headers)
    res = urllib.request.urlopen(req, timeout=5)
    # res = urllib.request.urlopen(url,timeout=5)
    html = res.read()
    # 解析html文件
    soup = BeautifulSoup(html, "html.parser")
    glsa_name = soup.select('body > div > div > div > h1')[0].text
    glsa_version = soup.select('body > div > div > div > h1 > small')[0].text
    affected_versions=soup.select('body > div > div > div > div > div.col-12.col-md-10 > div.table-responsive > table tr.table-danger > td')[0].text
    unaffected_versions=soup.select('body > div > div > div > div > div.col-12.col-md-10 > div.table-responsive > table  tr.table-success > td')[0].text
    idefntifiers=[]
    cve_list=soup.select('body > div > div > div > div > div.col-12.col-md-10 > ul > li>a')
    vulnerable_versions=unaffected_versions + ',' + affected_versions
    #获取cve列表
    for item in cve_list:
        if('CVE' in item.text ):
            if('(' not in item.text):
                get_cvss_info=get_cvss(item.text)
                idefntifiers_obj={}
                idefntifiers_obj['type']=item.text.split('-')[0]
                idefntifiers_obj['value']=item.text
                # 漏洞从哪个网站发现的
                idefntifiers_obj['source']=(glsa_version.split('—')[1]).strip()
                idefntifiers_obj['cvss']=get_cvss_info[0]
                idefntifiers_obj['cwes']=get_cvss_info[1]
                idefntifiers_obj['fixed_versions_and_patch']=get_cvss_info[2]
                idefntifiers_obj['vulnerable_apis_list']=get_cvss_info[3]
                idefntifiers.append(idefntifiers_obj)
    return  (idefntifiers,vulnerable_versions)
def get_cvss(id):
    url='https://nvd.nist.gov/vuln/detail/' + id
    # res = urllib.request.urlopen(url)
    print(url)
    req = urllib.request.Request(url, None, headers)
    res = urllib.request.urlopen(req, timeout=5)
    html = res.read()
    soup = BeautifulSoup(html, "html.parser")
    # cvss_version3_score= (soup.select('#Cvss3NistCalculatorAnchor')[0].text) if len(soup.select('#Cvss3NistCalculatorAnchor'))!=0 else ''
    # cvss_version3_vector=soup.select('#Vuln3CvssPanel > div.row.no-gutters > div.col-lg-6.col-sm-12 > span > span')[0].text
    # cvss_version2_score=soup.select('#Cvss2CalculatorAnchor')[0].text
    # cvss_version2_vector=soup.select('#Vuln2CvssPanel > div.row.no-gutters > div.col-lg-6.col-sm-12 > span > span')[0].text
    cvss_version3_score= ''
    cvss_version3_vector=''
    cvss_version2_score=''
    cvss_version2_vector=''
    #hyper_link_list
    hyper_link_list=soup.select('#vulnHyperlinksPanel > table tr')

    vulnerable_apis_list=[]
    hyper_link=[]
    for item in hyper_link_list[1:]:#每个link
        patch_list = []  # 已经修复的补丁链接
        #判断class='badge'里面是否有patch
        # vulnHyperlinksPanel > table > tbody > tr:nth-child(1) > td:nth-child(2)
        badge_list=item.select('td:nth-child(2)>span>span')
        patch_href=item.select('td:nth-child(1)>a')[0].text
        for badge_item in badge_list:
            if(badge_item.text=='Patch'):#跳出循环,去查询 patch补丁相关信息
                print(fixed_versions(patch_href))
                # if(fixed_versions(patch_href)!={}):
                hyper_link.append(fixed_versions(patch_href))
                vulnerable_apis_list+=get_vulnerable_apis(patch_href)

                # break
        # if(len(patch_list)!=0):
        #     hyper_link.append(patch_list)
    print(hyper_link)
    #cew获取
    cwe_list=soup.select('#vulnTechnicalDetailsDiv > table tr')
    obj = {
        'cvss_version2_score':cvss_version2_score,
        'cvss_version3_vector':cvss_version3_vector,
        'cvss_version3_score':cvss_version3_score,
        'cvss_version2_vector':cvss_version2_vector
    }
    cwes=[]
    for item in cwe_list[1:]:
        cwe_obj={}
        #有的cwe_id有a标签 有的只有span要区分下
        if(len(item.select('td:nth-child(1)>a'))!=0):
            cwe_id=item.select('td:nth-child(1)>a')[0].text
        else:
            cwe_id = item.select('td:nth-child(1)>span')[0].text
        cwe_name=item.select('td:nth-child(2)')[0].text
        cwe_obj['cwe_id']=cwe_id
        cwe_obj['cwe_name']=cwe_name
        cwes.append(cwe_obj)
    return (obj,cwes,hyper_link,vulnerable_apis_list)

'''
...
查询当前包是什么语言
'''
def fixed_versions(url):
    print(url)

    req = urllib.request.Request(url, None, headers)
    response = urllib.request.urlopen(req)
    patch_href=response.geturl()
    html = response.read()

    if('commit' in patch_href and 'github' in patch_href):#带commit的信息
        soup = BeautifulSoup(html, "html.parser")
        path = soup.select(
            '#repository-container-header > div.d-flex.mb-3.px-3.px-md-4.px-lg-5 > div > h1 > span.author.flex-self-stretch > a')[
            0].text
        path_library = \
        soup.select('#repository-container-header > div.d-flex.mb-3.px-3.px-md-4.px-lg-5 > div > h1 > strong > a')[
            0].text
        all_path_library = 'https://github.com/' + path + '/' + path_library + '/branch_commits'
        if('commits' in patch_href):
            stamp = patch_href.split('commits')[1]
        else:
            stamp = patch_href.split('commit')[1]
        versions_url = all_path_library + stamp
        commit_req = urllib.request.Request(versions_url, None, headers)
        res = urllib.request.urlopen(commit_req)
        html = res.read()
        soup = BeautifulSoup(html, "html.parser")
        modify_location=soup.select('.branch a')

        fixed_versions_list=soup.select('.js-details-container li a')
        fixed_versions_and_patch=[]
        obj={
            'patch': patch_href,
            'version':[]
        }
        for item in fixed_versions_list:
            obj['version'].append(item.text)
        return obj
    else: return  {}
def get_vulnerable_apis(patch_href):
    req = urllib.request.Request(patch_href, None, headers)
    response = urllib.request.urlopen(req, timeout=5)
    # req = urllib.request.Request(patch_href)
    # response = urllib.request.urlopen(req)
    patch_href = response.geturl()
    if ('commit' in patch_href and 'github' in patch_href):  # 带commit的信息
        res = urllib.request.urlopen(patch_href)
        html = res.read()
        soup = BeautifulSoup(html, "html.parser")
        vulnerable_file=''
        vulnerable_file_arr=soup.select(' div.file-header.d-flex.flex-md-row.flex-column.flex-md-items-center.file-header--expandable.js-file-header > div.file-info.flex-auto.min-width-0.mb-md-0.mb-2 > a')
        if(len(vulnerable_file_arr)!=0):
            vulnerable_file=soup.select(' div.file-header.d-flex.flex-md-row.flex-column.flex-md-items-center.file-header--expandable.js-file-header > div.file-info.flex-auto.min-width-0.mb-md-0.mb-2 > a')[0].text
        vulnerable_apis = []
        vulnerable_apis.append({
            'file':vulnerable_file,
            'api':[]
        })
        return  vulnerable_apis
    else:return []
def con_dbs(vulnerable_data):
    with client:
        db = client.vulnerabledb
        db.vulnerable_data.insert_one(vulnerable_data)
    time.sleep(1)
    print('插入成功')
if __name__=="__main__":
    client=MongoClient('mongodb://localhost:27017/')
    ask_glsa_list()


