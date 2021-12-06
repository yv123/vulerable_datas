import re
import scrapy
from tutorial.items import TutorialItem
import os
import sys
sys.path.append(os.path.split(os.path.abspath(os.path.dirname(__file__)))[0])
from spiders.get_cve_common import get_cvss,fixed_versions


class VulnerableDataSpider(scrapy.Spider):
    arr = []
    name = 'vulnerable_data_debian'
    start_urls = ['https://lists.debian.org/debian-security-announce/']
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
        'Authorization': "token"" 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"
    }
    def parse(self, response):
        list=response.xpath('//*[@id="content"]/div/ul/li')
        for li in list[18:19]:
            #共24个
            # print('year_str',year_str)
            year_str=li.xpath('.//a/text()').extract()[0]
            print('year_str', year_str)
            base='https://lists.debian.org/debian-security-announce/'+year_str+'/threads.html'
            yield scrapy.Request(base, callback=self.get_debian_year_list,meta={'year_str':year_str},dont_filter=True)
    def get_debian_year_list(self,response):
        year_str = response.meta['year_str']
        list=response.xpath('/html/body/ul/li')
        # item='https://github.com/gisle/html-parser/commit/b9aae1e43eb2c8e989510187cff0ba3e996f9a4c'
        # vulnerdate_obj = TutorialItem()
        # # 在cve页面获取信息
        # vulnerdate_obj['fixed_versions_and_patch'] = []
        # vulnerdate_obj['vulnerable_apis'] = []
        # vulnerdate_obj['vulnerable_code_snippet'] = []
        # vulnerdate_obj['program_language_of_source_code'] = ''
        # vulnerdate_obj['program_language_of_library'] = ''
        # yield scrapy.Request(item, callback=fixed_versions,
        #                      meta={'patch_href': item, 'vulnerdate_obj': vulnerdate_obj})
        # return
        count=0
        for li in list:
            count+=1
            href=li.xpath('.//strong/a/@href').extract()[0]
            text=li.xpath('.//strong/a/text()').extract()[0]
            base = 'https://lists.debian.org/debian-security-announce/' + year_str + '/'+href
            #从年份列表进入，筛选每个年份的页面
            yield scrapy.Request(base, callback=self.get_debian_year_detail,meta={'text':text,'count':count},dont_filter=True)
    def get_debian_year_detail(self,response):
        text = response.meta['text']
        count = response.meta['count']
        detail_str=response.xpath('/html/body/pre/text()[3]').extract()[0]

        str = re.findall(r'Package\s*:\s*(.*)\s*', detail_str)
        if(len(str)!=0):
            str=str[0]
        str1 = re.findall(r'(CVE-[0-9-]*)\s+', detail_str,re.IGNORECASE)
        str2 = re.findall(r'(CAN-[0-9-]*)\s+', detail_str,re.IGNORECASE)
        cve_str=str1+str2
        print('countcount----',count)
        print(cve_str)
        # self.arr=self.arr+cve_str
        # print(self.arr)
        print('countcount-333333333333', count)
        if(len(cve_str)!=0):
            for item in cve_str:
                if('CAN' in item):
                    item=item.replace('CAN','CVE')
                print("CVE????????????????")
                print(item)
                print("CVE???????????????111111111")
                vulnerdate_obj = TutorialItem()
                vulnerdate_obj['vulnerable_library'] = str
                vulnerdate_obj['identifiers'] = [
                    {
                        'type': item.split('-')[0],
                        'value': item
                    },
                    {
                        'type': 'debian',
                        'value':text
                    }
                ]
                vulnerdate_obj['fixed_versions_and_patch'] = []
                vulnerdate_obj['vulnerable_apis'] = []
                vulnerdate_obj['vulnerable_code_snippet'] = []
                vulnerdate_obj['program_language_of_source_code'] = ''
                vulnerdate_obj['program_language_of_library'] = ''
                get_cvss_url = 'https://nvd.nist.gov/vuln/detail/' + item
                yield scrapy.Request(get_cvss_url, callback=get_cvss,
                                     meta={'vulnerdate_obj': vulnerdate_obj}, dont_filter=True)
