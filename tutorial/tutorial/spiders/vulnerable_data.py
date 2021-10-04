import scrapy

from bs4 import BeautifulSoup
import  time
from tutorial.items import TutorialItem
# from lxml import etree
import urllib.request
class VulnerableDataSpider(scrapy.Spider):
    name = 'vulnerable_data'
    # allowed_domains = ['www.baidu.com']
    start_urls = ['https://glsa.gentoo.org/glsa']
    def get_glsa_package_detail_info(self,response):
        vulnerdate_obj=response.meta['vulnerdate_item']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        glsa_name = soup.select('body > div > div > div > h1')[0].text
        glsa_version = soup.select('body > div > div > div > h1 > small')[0].text
        affected_versions = soup.select(
            'body > div > div > div > div > div.col-12.col-md-10 > div.table-responsive > table tr.table-danger > td')[
            0].text
        unaffected_versions = soup.select(
            'body > div > div > div > div > div.col-12.col-md-10 > div.table-responsive > table  tr.table-success > td')[
            0].text
        cve_list = soup.select('body > div > div > div > div > div.col-12.col-md-10 > ul > li>a')
        vulnerdate_obj['vulnerable_library'] = soup.select('body > div > div > div > h1.first-header')[0].text
        vulnerable_versions = unaffected_versions + ',' + affected_versions
        vulnerdate_obj['vulnerable_versions'] = vulnerable_versions
        vulnerdate_obj['identifiers'] = []
        # 获取cve列表
        count=0
        for item in cve_list:
            count = count + 1
            if ('CVE' in item.text and '(' not in item.text):

                get_cvss_url = 'https://nvd.nist.gov/vuln/detail/' + item.text
                # # 在cve页面获取信息
                identifiers_obj = {}
                identifiers_obj['type'] = item.text.split('-')[0]
                identifiers_obj['value'] = item.text
                # 漏洞从哪个网站发现的
                identifiers_obj['source'] = (glsa_version.split('—')[1]).strip()
                identifiers_obj['fixed_versions_and_patch'] = []
                vulnerdate_obj['identifiers'].append(identifiers_obj)
                yield scrapy.Request(get_cvss_url, callback=self.get_cvss,
                                     meta={'vulnerdate_obj': vulnerdate_obj,'index':count,'cve_id':item.text})

        # yield vulnerdate_obj
    def get_cvss(self,response):
        vulnerdate_obj = response.meta['vulnerdate_obj']
        index = response.meta['index']
        cve_id = response.meta['cve_id']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        cvss_version3_score= (soup.select('#Vuln3CvssPanel .no-gutters'))
        cvss3_list=[]
        for item in cvss_version3_score:
            cvss3_obj={}
            from_2=item.select('div:nth-child(2) > div > div.col-lg-9.col-sm-6 > span')[0].text
            base_score=item.select('.severityDetail a')[0].text
            Vector=item.select('div:nth-child(4)>span>span')[0].text
            cvss3_obj['type']=from_2
            cvss3_obj['base_score']=base_score
            cvss3_obj['Vector']=Vector
            cvss3_list.append(cvss3_obj)
        cvss_version2_score = (soup.select('#Vuln2CvssPanel .no-gutters'))
        cvss2_list = []
        for item1 in cvss_version2_score:
            cvss2_obj = {}
            from_2 = item1.select('div:nth-child(1) > div > div.col-lg-9.col-sm-6 > span')[0].text
            base_score = item1.select('.severityDetail a')[0].text
            Vector = item1.select('div:nth-child(3)>span>span')[0].text
            cvss2_obj['type'] = from_2
            cvss2_obj['base_score'] = base_score
            cvss2_obj['Vector'] = Vector
            cvss2_list.append(cvss2_obj)
        cvss={
            'CVSSVersion3':cvss3_list,
            'CVSSVersion2':cvss2_list
        }

        # cew获取
        cwe_list = soup.select('#vulnTechnicalDetailsDiv > table tr')
        cwes = []
        for item in cwe_list[1:]:
            cwe_obj = {}
            # 有的cwe_id有a标签 有的只有span要区分下
            if (len(item.select('td:nth-child(1)>a')) != 0):
                cwe_id = item.select('td:nth-child(1)>a')[0].text
            else:
                cwe_id = item.select('td:nth-child(1)>span')[0].text
            cwe_name = item.select('td:nth-child(2)')[0].text
            cwe_obj['cwe_id'] = cwe_id
            cwe_obj['cwe_name'] = cwe_name
            cwes.append(cwe_obj)
        vulnerdate_obj['identifiers'][index - 1]['cvss'] = cvss
        vulnerdate_obj['identifiers'][index - 1]['cwes'] = cwes
        # hyper_link_list
        hyper_link_list = soup.select('#vulnHyperlinksPanel > table tr')
        hyper_link = []
        for item in hyper_link_list[1:]:  # 每个link
            # patch_list = []  # 已经修复的补丁链接
            patch_href = item.select('td:nth-child(1)>a')[0].text
            if(('github' in patch_href and 'commit' in patch_href) or ('gitlab' in patch_href and 'commit' in patch_href)):
                #github上的链接
                hyper_link.append(patch_href)
        if(len(hyper_link)!=0):
            hyper_link_index=0
            for item in hyper_link:
                yield scrapy.Request(item, callback=self.fixed_versions,
                               meta={'patch_href': item,'vulnerdate_obj':vulnerdate_obj,'cve_id':cve_id,'index':index,
                                     'identifiers_item':vulnerdate_obj['identifiers'][index-1],'hyper_link_len':len(hyper_link),
                                     'hyper_link_index':hyper_link_index})
        else:
            yield vulnerdate_obj
    def fixed_versions(self,response):
        index = response.meta['index']
        cve_id = response.meta['cve_id']
        patch_href = response.meta['patch_href']
        hyper_link_len = response.meta['hyper_link_len']
        hyper_link_index = response.meta['hyper_link_index']
        vulnerdate_obj = response.meta['vulnerdate_obj']
        identifiers_item = response.meta['identifiers_item']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        if ('commit' in patch_href and 'github' in patch_href):  # 带commit的信息
            # repository-container-header > div.d-flex.mb-3.px-3.px-md-4.px-lg-5
            path = soup.select('#repository-container-header > div.d-flex.mb-3.px-3.px-md-4.px-lg-5 > div > h1 > span.author.flex-self-stretch > a')[0].text
            path_library = soup.select(
                    '#repository-container-header > div.d-flex.mb-3.px-3.px-md-4.px-lg-5 > div > h1 > strong > a')[
                    0].text
            all_path_library = 'https://github.com/' + path + '/' + path_library + '/branch_commits'
            if ('commits' in patch_href):
                stamp = patch_href.split('commits')[1]
            else:
                stamp = patch_href.split('commit')[1]
            versions_url = all_path_library + stamp

            yield scrapy.Request(versions_url, callback=self.get_versions,
                                 meta={'vulnerdate_obj': vulnerdate_obj,'patch_href':patch_href,'cve_id':cve_id,
                                       'index':index,'hyper_link_len':hyper_link_len,
                                     'hyper_link_index':hyper_link_index})
        if ('commit' in patch_href and 'gitlab' in patch_href):  # 带commit的信息
            all_path_library =response.request.url+ '/branches'
            versions_url = all_path_library

            yield scrapy.Request(versions_url, callback=self.get_versions,
                                 meta={'vulnerdate_obj': vulnerdate_obj,'patch_href':patch_href,'cve_id':cve_id,
                                       'index':index,'hyper_link_len':hyper_link_len,
                                     'hyper_link_index':hyper_link_index})

    def get_versions(self,response):
        vulnerdate_obj = response.meta['vulnerdate_obj']
        index = response.meta['index']
        patch_href = response.meta['patch_href']
        hyper_link_len = response.meta['hyper_link_len']
        hyper_link_index = response.meta['hyper_link_index']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        if('commit' in patch_href and 'gitlab' in patch_href):
            fixed_versions_list=soup.select(' span > span > a.badge')
        else:
            fixed_versions_list = soup.select('.js-details-container li a')
        fixed_versions_and_patch = []
        obj = {
            'patch': patch_href,
            'file_path': '',
            'version': []
        }
        for item in fixed_versions_list:
            obj['version'].append(item.text)
        yield scrapy.Request(patch_href, callback=self.get_file_path,
                             meta={'vulnerdate_obj': vulnerdate_obj,'fixed_versions_item':obj,'index':index,'patch_href':patch_href},dont_filter=True)
        # yield vulnerdate_obj
    def get_file_path(self,response):
        vulnerdate_obj = response.meta['vulnerdate_obj']
        index = response.meta['index']
        obj = response.meta['fixed_versions_item']
        patch_href = response.meta['patch_href']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        if ('commit' in patch_href and 'github' in patch_href):
            file_path = soup.select(
                'div.file-header.d-flex.flex-md-row.flex-column.flex-md-items-center.file-header--expandable.js-file-header > div.file-info.flex-auto.min-width-0.mb-md-0.mb-2 > a')[
                0].text
        else:
            file_path=soup.select('div.js-file-title.file-title-flex-parent.is-commit > div.file-header-content > a > strong')[0].text
        obj['file_path']=file_path
        vulnerdate_obj['identifiers'][index - 1]['fixed_versions_and_patch'].append(obj)
        yield vulnerdate_obj
    def parse(self, response):
        html_doc = response.body
        soup = BeautifulSoup(html_doc,"html.parser")
        glsa_list = soup.select('body > div > div > div > div.table-responsive.mb-3 > table   tr')
        dataList = []
        print('start')
        index=0
        for item in glsa_list[1900:2200]:
            glsa_id = item.select('th a')[0].text
            # glsa_id='202105-10'
            detail_url ='https://glsa.gentoo.org/glsa/'+glsa_id
            vulnerdate_obj=TutorialItem()
            vulnerdate_obj['glsa_id']=glsa_id
            index=index+1
            print(index)
            #给详情页面发送请求
            yield scrapy.Request(detail_url, callback=self.get_glsa_package_detail_info,meta={'vulnerdate_item':vulnerdate_obj})
        # print('all over')

