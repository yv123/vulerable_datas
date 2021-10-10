import re
import scrapy
from bs4 import BeautifulSoup
from tutorial.code import Language_code_arr
from tutorial.items import TutorialItem
class VulnerableDataSpider(scrapy.Spider):
    name = 'vulnerable_data'
    start_urls = ['https://glsa.gentoo.org/glsa']
    judge_language=Language_code_arr()
    def get_glsa_package_detail_info(self,response):
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        affected_versions = soup.select(
            'body > div > div > div > div > div.col-12.col-md-10 > div.table-responsive > table tr.table-danger > td')[
            0].text
        unaffected_versions = soup.select(
            'body > div > div > div > div > div.col-12.col-md-10 > div.table-responsive > table  tr.table-success > td')[
            0].text
        cve_list = soup.select('body > div > div > div > div > div.col-12.col-md-10 > ul > li>a')
        vulnerable_versions = unaffected_versions + ',' + affected_versions
        glsa_version = soup.select('body > div > div > div > h1 > small')[0].text
        # 获取cve列表
        for item in cve_list:
            if ('CVE' in item.text and '(' not in item.text):
                vulnerdate_obj = TutorialItem()
                vulnerdate_obj['vulnerable_library'] = response.meta['vulnerable_library']
                vulnerdate_obj['vulnerable_versions'] = vulnerable_versions
                vulnerdate_obj['identifiers'] = [
                    {
                        'type':item.text.split('-')[0],
                        'value':item.text
                    },
                    {
                        'type': 'GLSA',
                        'value': (glsa_version.split('—')[1]).strip()
                    }
                ]
                get_cvss_url = 'https://nvd.nist.gov/vuln/detail/' + item.text
                # # 在cve页面获取信息
                vulnerdate_obj['fixed_versions_and_patch'] = []
                vulnerdate_obj['vulnerable_apis'] = []
                vulnerdate_obj['vulnerable_code_snippet'] = []
                vulnerdate_obj['program_language_of_source_code'] = ''
                vulnerdate_obj['program_language_of_library'] = ''
                yield scrapy.Request(get_cvss_url, callback=self.get_cvss,
                                     meta={'vulnerdate_obj': vulnerdate_obj})
    def get_cvss(self,response):
        vulnerdate_obj = response.meta['vulnerdate_obj']
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
        vulnerdate_obj['cvss'] = cvss
        vulnerdate_obj['cwes'] = cwes
        # hyper_link_list
        hyper_link_list = soup.select('#vulnHyperlinksPanel > table tr')
        hyper_link = []
        for item in hyper_link_list[1:]:  # 每个link
            # patch_list = []  # 已经修复的补丁链接
            patch_href = item.select('td:nth-child(1)>a')[0].text
            if(('github' in patch_href and '/commit/' in patch_href) or ('gitlab' in patch_href and 'commit' in patch_href)):
                #github上的链接
                hyper_link.append(patch_href)
        if(len(hyper_link)!=0):
            for item in hyper_link:
                #获取file及apis function_name
                yield scrapy.Request(item, callback=self.fixed_versions,
                               meta={'patch_href': item,'vulnerdate_obj':vulnerdate_obj})
        else:
            yield vulnerdate_obj
    def fixed_versions(self,response):
        patch_href = response.meta['patch_href']
        vulnerdate_obj = response.meta['vulnerdate_obj']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        if ('commit' in patch_href and 'github' in patch_href):  # 带commit的信息
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
            #获取版本号的url链接
            yield scrapy.Request(versions_url, callback=self.get_versions,
                                 meta={'vulnerdate_obj': vulnerdate_obj,'patch_href':patch_href})
        if ('commit' in patch_href and 'gitlab' in patch_href):  # 带commit的信息
            all_path_library =response.request.url+ '/branches'
            versions_url = all_path_library

            yield scrapy.Request(versions_url, callback=self.get_versions,
                                 meta={'vulnerdate_obj': vulnerdate_obj,'patch_href':patch_href})

    def get_versions(self,response):
        vulnerdate_obj = response.meta['vulnerdate_obj']
        patch_href = response.meta['patch_href']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        if('commit' in patch_href and 'gitlab' in patch_href):
            fixed_versions_list=soup.select(' span > span > a.badge')
        else:
            fixed_versions_list = soup.select('.js-details-container li a')
        obj = {
            'patch': patch_href,
            'version': []
        }
        for item in fixed_versions_list:
            obj['version'].append(item.text)
        yield scrapy.Request(patch_href, callback=self.get_file_path,
                             meta={'vulnerdate_obj': vulnerdate_obj,'fixed_versions_item':obj,'patch_href':patch_href},dont_filter=True)
    def get_file_path(self,response):
        vulnerdate_obj = response.meta['vulnerdate_obj']
        obj = response.meta['fixed_versions_item']
        patch_href = response.meta['patch_href']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        print(patch_href)
        if ('commit' in patch_href and 'github' in patch_href):
            abc=soup.select('#files > div.js-diff-progressive-container .js-details-container')
            for item1 in abc:
                obj1={}
                bbb=item1.select('div.file-header.d-flex.flex-md-row.flex-column.flex-md-items-center.file-header--expandable.js-file-header > div.file-info.flex-auto.min-width-0.mb-md-0.mb-2 > a')
                obj1['file']=bbb[0].text
                file_to_judge_language=Language_code_arr()
                if(file_to_judge_language[obj1['file'].split('.')[1]]):
                    vulnerdate_obj['program_language_of_source_code']=file_to_judge_language[obj1['file'].split('.')[1]]
                obj1['api']=[]
                ccc=item1.select('.js-expandable-line')
                for li in ccc[:-1]:
                   fff= li.select('.blob-code-hunk')
                   new_funct_name = re.findall(r"@@.*?@@ (.*)\(", fff[0].text)
                   if(new_funct_name):
                       print(new_funct_name[0]+'()')
                       obj1['api'].append(new_funct_name[0]+'()')
                vulnerdate_obj['vulnerable_apis'].append(obj1)
        else:
            abc=soup.select('.file-holder')
            for item1 in abc:
                obj1 = {}
                bbb=item1.select('div.js-file-title.file-title-flex-parent.is-commit > div.file-header-content > a > strong')
                obj1['file'] = bbb[0].text.replace('\n','')
                file_to_judge_language1 = Language_code_arr()
                if (file_to_judge_language1.get((obj1['file'].split('.')[1]).replace('\n',''))):
                    vulnerdate_obj['program_language_of_source_code'] = file_to_judge_language1.get((obj1['file'].split('.')[1]).replace('\n',''))
                obj1['api'] = []
                ccc=item1.select('table .line_holder.match')
                for li in ccc[:-1]:
                    function_name=li.select('.line_content.match')[0].text
                    print(function_name)
                    new_funct_name = re.findall(r"@@.*?@@ (.*)\(", function_name)
                    if (new_funct_name):
                        obj1['api'].append(new_funct_name[0] + '()')
                vulnerdate_obj['vulnerable_apis'].append(obj1)
        vulnerdate_obj['fixed_versions_and_patch'].append(obj)
        yield vulnerdate_obj
    def parse(self, response):
        html_doc = response.body
        soup = BeautifulSoup(html_doc,"html.parser")
        glsa_list = soup.select('body > div > div > div > div.table-responsive.mb-3 > table   tr')
        for item in glsa_list[184:185]:
            glsa_id = item.select('th a')[0].text
            detail_url ='https://glsa.gentoo.org/glsa/'+glsa_id
            vulnerable_library=item.select('td')[0].text.split(':')[0]
            #给详情页面发送请求
            yield scrapy.Request(detail_url, callback=self.get_glsa_package_detail_info,meta={'vulnerable_library':vulnerable_library})

