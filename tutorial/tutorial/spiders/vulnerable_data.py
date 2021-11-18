import re
import scrapy
from bs4 import BeautifulSoup
from tutorial.items import TutorialItem
import json
class VulnerableDataSpider(scrapy.Spider):
    name = 'vulnerable_data'
    start_urls = ['https://glsa.gentoo.org/glsa']
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
        'Authorization': "token"" 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"
    }
    #通过glsa的id查询详细信息
    def get_glsa_package_detail_info(self,response):
        print(0)
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        affected_versions = soup.select(
            'body > div > div > div > div > div.col-12.col-md-10 > div.table-responsive > table tr.table-danger > td')[
            0].text
        unaffected_versions = soup.select(
            'body > div > div > div > div > div.col-12.col-md-10 > div.table-responsive > table  tr.table-success > td')[
            0].text
        cve_list = soup.select('body > div > div > div > div > div.col-12.col-md-10 > ul > li>a')
        glsa_version = soup.select('body > div > div > div > h1 > small')[0].text
        # 获取cve列表
        for item in cve_list:
            if ('CVE' in item.text and '(' not in item.text):
                print(item.text)
                vulnerdate_obj = TutorialItem()
                vulnerdate_obj['vulnerable_library'] = response.meta['vulnerable_library']
                vulnerdate_obj['unaffected_versions'] = unaffected_versions
                vulnerdate_obj['affected_versions'] = affected_versions
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
                get_cvss_url ='https://nvd.nist.gov/vuln/detail/'+item.text
                # # 在cve页面获取信息
                vulnerdate_obj['fixed_versions_and_patch'] = []
                vulnerdate_obj['vulnerable_apis'] = []
                vulnerdate_obj['vulnerable_code_snippet'] = []
                vulnerdate_obj['program_language_of_source_code'] = ''
                vulnerdate_obj['program_language_of_library'] = ''
                print(get_cvss_url)
                yield scrapy.Request(get_cvss_url, callback=self.get_cvss,
                                     meta={'vulnerdate_obj': vulnerdate_obj},dont_filter=True)
    def get_cvss(self,response):
        print('9999999999999999999')
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
            from_2 = item1.select('div:nth-child(1)>div .col-lg-9 strong')[0].text
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
            patch_href = item.select('td:nth-child(1)>a')[0].text
            if(('github' in patch_href and '/commit/' in patch_href)):
                #github上的链接
                hyper_link.append(patch_href)
            elif(('gitlab' in patch_href and '/commit/' in patch_href)):
                hyper_link.append(patch_href)
        print(hyper_link)
        if(len(hyper_link)!=0):
            for item in hyper_link:
                #获取file及apis function_name
                # print(hyper_link)
                yield scrapy.Request(item, callback=self.fixed_versions,
                               meta={'patch_href': item,'vulnerdate_obj':vulnerdate_obj},dont_filter=True)

        else:
            yield vulnerdate_obj
    def fixed_versions(self,response):
        patch_href = response.meta['patch_href']
        vulnerdate_obj = response.meta['vulnerdate_obj']
        print('fixed_versions1')
        print('fixed_versions2')
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        if ('commit' in patch_href and 'github' in patch_href):  # 带commit的信息
            print(1)
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
        elif('commit' in patch_href and 'gitlab' in patch_href):
            versions_url = response.url + '/branches'
        yield scrapy.Request(versions_url, callback=self.get_versions,
                             meta={'vulnerdate_obj': vulnerdate_obj, 'patch_href': patch_href},dont_filter=True)
    def get_versions(self,response):
        vulnerdate_obj = response.meta['vulnerdate_obj']
        patch_href = response.meta['patch_href']
        print('get_versions_1')
        print('get_versions_2')
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        if('commit' in patch_href and 'github' in patch_href):
            fixed_versions_list = soup.select('.js-details-container li a')
        elif('commit' in patch_href and 'gitlab' in patch_href):
            fixed_versions_list = soup.select('.js-details-content  a')
        obj = {
            'patch': patch_href,
            'version': []
        }
        for item in fixed_versions_list:
            obj['version'].append(item.text)
        print('1111111111111111')
        print(obj)
        print('hhhhhhhhhhhhh')
        vulnerdate_obj['fixed_versions_and_patch'].append(obj)
        yield scrapy.Request(patch_href, callback=self.get_file_path,
                             meta={'vulnerdate_obj': vulnerdate_obj,'fixed_versions_item':obj,'patch_href':patch_href},dont_filter=True)
    def get_file_path(self,response):
        vulnerdate_obj = response.meta['vulnerdate_obj']
        obj = response.meta['fixed_versions_item']
        print('get_file_path1')
        print('get_file_path2')
        patch_href = response.meta['patch_href']
        html_doc = response.body
        soup = BeautifulSoup(html_doc, "html.parser")
        if ('commit' in patch_href and 'github' in patch_href):
            abc=soup.select('#files > div.js-diff-progressive-container .js-details-container')
            for item1 in abc:
                obj1={}
                bbb=item1.select('div.file-header.d-flex.flex-md-row.flex-column.flex-md-items-center.file-header--expandable.js-file-header > div.file-info.flex-auto.min-width-0.mb-md-0.mb-2 > a')
                #获取文件名
                obj1['file']=(bbb[0].text).replace('\n','')
                print(obj1['file'])
                obj1['code_line']=[]
                if(len(obj1['file'].split('.'))>=2):
                    file_type = obj1['file'].split('/')[-1].split('.')[-1]
                else:
                    file_type=''
                #获取table下面的 tr列表
                ccc=item1.select('table tr.js-expandable-line')
                #增加的代码行
                blob_num_addition_arr=item1.select('tr .blob-num.blob-num-addition.js-linkable-line-number')
                #删除的代码行
                blob_num_deletion_arr = item1.select('tr .blob-num.blob-num-deletion.js-linkable-line-number')
                blob_num_addition_parent_arr=[]
                for li in blob_num_addition_arr:
                    parent=li.parent
                    ll=parent.select('.blob-num.blob-num-addition.js-linkable-line-number')[0]['data-line-number']
                    blob_num_addition_parent_arr.append(ll)
                #遍历删除的代码行，然后记录它的上一行的代码数，然后append到blob_num_addition_parent_arr中
                for li in blob_num_deletion_arr:
                    parent=li.parent
                    parent_previous_sibling=parent.find_previous_sibling()
                    while(parent_previous_sibling.select('td:nth-child(2)')[0].has_attr('data-line-number') == False):
                        parent_previous_sibling=parent_previous_sibling.find_previous_sibling()
                    current_line=parent_previous_sibling.select('td:nth-child(2)')[0]['data-line-number']
                    if(current_line.isdigit()):
                        if(str(int(current_line)+1) not in blob_num_addition_parent_arr):
                            blob_num_addition_parent_arr.append(str(int(current_line)+1)) #将删除的代码行的上一行记录下来
                obj1['blob_num_addition_parent_arr'] = blob_num_addition_parent_arr
                for li in ccc:
                   fff= li.select('.blob-code-hunk')
                   if(fff[0].text ):
                       modify_line_arr = re.findall(r'@@(.*?)@@', fff[0].text)[0].split('+')[1].split(',')

                       modify_line_arr_to_num = list(map(int, modify_line_arr))
                       #修改代码段的开始行
                       start_line = modify_line_arr_to_num[0]
                       #修改代码段的结束行
                       end_line = modify_line_arr_to_num[0] + modify_line_arr_to_num[1] - 1
                       obj1['code_line'].append(str(start_line)+'-'+str(end_line))
                       #拿到代码行要去爬取raw_url
                #不需要爬取api了
                raw_url_1 = re.findall(r"(.*)/commit", patch_href)[0]
                commit_sha = re.findall(r"commit/(.*)", patch_href)[0]
                get_raw_url= raw_url_1 + '/blob/' + commit_sha+'/'+bbb[0].text
                print('file_type',file_type,file_type == 'c' or file_type == 'h')
                if (file_type == 'c' or file_type == 'h'):
                    vulnerdate_obj['program_language_of_source_code'] = file_type
                    yield scrapy.Request(get_raw_url, callback=self.get_snipaste_code,
                                     meta={'vulnerdate_obj': vulnerdate_obj,'vulnerable_apis':obj1,'patch_href': patch_href},dont_filter=True)
                else:
                    yield vulnerdate_obj
        elif('commit' in patch_href and 'gitlab' in patch_href):
            print(3)
            abc = soup.select('.files .diff-file.file-holder')
            for item1 in abc:
                obj1 = {}
                bbb = item1.select(
                    'div.js-file-title.file-title-flex-parent.is-commit > div.file-header-content > a > strong')
                obj1['file'] = (bbb[0].text).replace('\n', '')
                obj1['code_line'] = []
                file_type = ''
                if (len(obj1['file'].split('.')) >= 2):
                    file_type = obj1['file'].split('.')[1]
                else:
                    file_type = ''
                ccc = item1.select('table tr.line_holder.match')
                blob_num_addition_arr = item1.select('.line_holder.new')
                #删除的代码行
                blob_num_deletion_arr = item1.select('.line_holder.old')
                blob_num_addition_parent_arr = []
                for li in blob_num_addition_arr:
                    ll = li.select('.new_line.diff-line-num.new')[0]['data-linenumber']
                    blob_num_addition_parent_arr.append(ll)

                # 遍历删除的代码行，然后记录它的上一行的代码数，然后append到blob_num_addition_parent_arr中
                for li in blob_num_deletion_arr:
                    current_line=li.select('td:nth-child(2)')[0]['data-linenumber']
                    if (current_line.isdigit()):
                        if (str(int(current_line)) not in blob_num_addition_parent_arr):
                            blob_num_addition_parent_arr.append(str(int(current_line)))  # 将删除的代码行的上一行记录下来
                obj1['blob_num_addition_parent_arr'] = blob_num_addition_parent_arr
                for li in ccc:
                    fff = li.select('.line_content.match')
                    if (fff[0].text):
                        modify_line_arr = re.findall(r'@@(.*?)@@', fff[0].text)[0].split('+')[1].split(',')
                        modify_line_arr_to_num = list(map(int, modify_line_arr))
                        # 修改代码段的开始行
                        start_line = modify_line_arr_to_num[0]
                        # 修改代码段的结束行
                        end_line = modify_line_arr_to_num[0] + modify_line_arr_to_num[1] - 1
                        obj1['code_line'].append(str(start_line) + '-' + str(end_line))
                        # 拿到代码行要去爬取raw_url
                # 不需要爬取api了
                raw_url_1 = re.findall(r"(.*)/commit", patch_href)[0]
                commit_sha = re.findall(r"commit/(.*)", patch_href)[0]
                get_raw_url = raw_url_1 + '/blob/' + commit_sha + '/' + bbb[0].text+'?format=json&viewer=simple'
                if (file_type == 'c' or file_type == 'h'):
                    vulnerdate_obj['program_language_of_source_code'] = file_type
                    yield scrapy.Request(get_raw_url, callback=self.get_snipaste_gitlab_code,
                                     meta={'vulnerdate_obj': vulnerdate_obj, 'vulnerable_apis': obj1,
                                           'patch_href': patch_href},dont_filter=True)
                else:
                    yield vulnerdate_obj
    def get_snipaste_code(self,response):
        vulnerable_apis = response.meta['vulnerable_apis']
        vulnerdate_obj = response.meta['vulnerdate_obj']
        vulnerable_apis['vulnerable_apis']=[]
        print(4)
        print(vulnerable_apis['code_line'])
        print(vulnerable_apis)
        if(len(vulnerable_apis['code_line'])!=0):
            # current_line;
            for item in vulnerable_apis['code_line']:
                start_line=int(item.split('-')[0])
                end_line=int(item.split('-')[1])
                current_line=end_line
                remain_modified_line_nums=0
                while current_line>0 and (current_line>=start_line or remain_modified_line_nums>0):
                    current_code_str = response.xpath('string(//*[@id="LC'+str(current_line)+'"])').extract()[0]
                    print(current_line)
                    print(current_code_str)
                    print(str(current_line) in vulnerable_apis['blob_num_addition_parent_arr'])
                    #当前行是修改的行 那么漏洞函数有可能在它的上方，有可能他是漏洞函数（修改的是当前函数参数）
                    if(str(current_line) in vulnerable_apis['blob_num_addition_parent_arr']):
                    # if(str(current_line) in vulnerable_apis['blob_num_addition_parent_arr'] and (current_code_str[0].isspace() == True or current_code_str[0]=='}')):
                        #代表当前行是新增或者删除的漏洞的代码行
                        remain_modified_line_nums+=1
                        current_line -= 1
                    else:
                        print(remain_modified_line_nums)
                        if(remain_modified_line_nums>0):
                            current_code_str = delcommonds(current_code_str)
                            if(len(current_code_str.strip())>0):
                                if(current_code_str[0]=='}' or current_line==1):
                                    #碰到右括号，代表上一个函数结束那么
                                    #判断remain_modified_line_nums如果不为0 那么向下扫描
                                    if(remain_modified_line_nums >0):
                                        # current_line+=1
                                        # remain_modified_line_nums=0
                                        print('下一个')
                                        if(current_line==1):
                                            function_name_str=from_current_line_find_before(response,current_line)
                                        else:
                                            function_name_str = from_current_line_find_before(response,current_line+1)
                                        function_name_body_title = re.findall(
                                            r'([A-Za-z_0-9()]+\s*[\\*]*\s*[A-Za-z_0-9]+\s*\([^)]*\))',
                                            function_name_str)
                                        print("xixixi")
                                        print(function_name_body_title)
                                        print("hhhh")
                                        if (len(function_name_body_title) != 0):
                                            vulnerable_apis['vulnerable_apis'].append(function_name_body_title[0])
                                    current_line -= 1
                                    remain_modified_line_nums = 0
                                elif(current_code_str[0]=='{'):
                                    print('------')
                                    #那么向上3行代码 就能匹配到函数
                                    # 从当前行往前扫描 直到扫描到（左括号
                                    current_line -= 1
                                    function_name_str = ''
                                    if (response.xpath('string(//*[@id="LC' + str(current_line) + '"])')):
                                        while (response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip() != ''
                                        and response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip() !='*/'
                                        and response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip()[0] !='#'
                                        and response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip()[0] !='}'):
                                            print('[[[[')
                                            print(response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip() !='#')
                                            print(response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t',''))
                                            print('||||')
                                            function_name_str = delcommonds(response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').rstrip() )+ ' ' + function_name_str
                                            current_line -= 1
                                    print('000000')

                                    print(function_name_str)
                                    print('11111')
                                    function_name_str = delcommonds(function_name_str)
                                    function_name_body_title = re.findall(r'([A-Za-z_0-9()]+\s*[\\*]*\s*[A-Za-z_0-9]+\s*\([^)]*\))',
                                                                          function_name_str)
                                    print('ss',function_name_body_title)
                                    print('ss',len(function_name_body_title))
                                    if(len(function_name_body_title)!=0):
                                        print('99',function_name_body_title[0] not in  vulnerable_apis['vulnerable_apis'])
                                        if(function_name_body_title[0] not in  vulnerable_apis['vulnerable_apis']):
                                            vulnerable_apis['vulnerable_apis'].append(function_name_body_title[0])
                                    current_line-=3
                                    remain_modified_line_nums=0
                                elif(current_code_str[0].isspace() == False and current_code_str[0] != '{' and current_code_str[0] !='#' and '{' in current_code_str):
                                    print(']]]]]]]]')
                                    function_name_str=''
                                    if (response.xpath('string(//*[@id="LC' + str(current_line) + '"])')):
                                        while (response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip() != ''
                                        and response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip() !='*/'
                                        # and '//' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t', '').strip()
                                        and response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip()[0] !='#'):
                                            function_name_str = delcommonds(response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').rstrip()) + ' ' + function_name_str
                                            current_line -= 1
                                    remain_modified_line_nums = 0
                                    # 去掉注释
                                    current_code_str = delcommonds(function_name_str)
                                    function_name_body_title = re.findall(
                                        r'([A-Za-z_0-9()]+\s*[\\*]*\s*[A-Za-z_0-9]+\s*\([^)]*\))',
                                        current_code_str)
                                    if (len(function_name_body_title) != 0):
                                        if (function_name_body_title[0] not in vulnerable_apis['vulnerable_apis']):
                                            vulnerable_apis['vulnerable_apis'].append(function_name_body_title[0])
                                elif (current_code_str[0].isspace() == True and '{' in current_code_str and '}' not in  current_code_str and len(current_code_str.strip())!=1 and
                                      'if' not in current_code_str
                                and  ';' not in current_code_str and  'else' not in current_code_str
                                      and  'switch' not in current_code_str and 'case' not in current_code_str
                                      and  'while' not in current_code_str and 'switch' not in current_code_str and 'for' not in current_code_str
                                      and ' do' not in current_code_str):
                                    function_name_str=''
                                    if (response.xpath('string(//*[@id="LC' + str(current_line) + '"])')):
                                        while (response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip() != ''
                                        and response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip() !='*/'
                                        # and ' // ' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and ' if ' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and 'switch' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and 'case' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and 'else' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and ' do' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and 'for' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and 'while' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and 'switch' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
                                        and response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip()[0] !='#'):
                                            function_name_str = delcommonds(response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').rstrip()) + ' ' + function_name_str
                                            current_line -= 1
                                    print('0000000000000000')
                                    print(current_code_str.strip())
                                    print(len(current_code_str.strip())!=1)
                                    print(len(current_code_str.strip()))
                                    print(function_name_str)
                                    function_name_str = delcommonds(function_name_str)
                                    print(function_name_str)
                                    print('1111111111111111')
                                    # 去掉注释
                                    if(len(function_name_str.strip()) !=0 and ' if ' not in function_name_str  and  'switch' not in function_name_str
                                            and  'case' not in function_name_str and   'else' not in function_name_str
                                            and ' do' not in function_name_str and 'for' not in function_name_str
                                            and 'while' not in function_name_str and 'switch' not in function_name_str):
                                        function_name_body_title = re.findall(
                                            r'([A-Za-z_0-9()]+\s*[\\*]*\s*[A-Za-z_0-9]+\s*\([^)]*\))',
                                            function_name_str)
                                        print('-----------------------')
                                        print(function_name_body_title)
                                        print(len(function_name_body_title))
                                        print('--------------------------')
                                        if (len(function_name_body_title) != 0):
                                            print('0011111')
                                            print(function_name_body_title[0])
                                            if (function_name_body_title[0] not in vulnerable_apis['vulnerable_apis']):
                                                vulnerable_apis['vulnerable_apis'].append(function_name_body_title[0])
                                            remain_modified_line_nums=0
                                else:
                                    current_line-=1
                            else:
                                #向上扫描碰到空格的时候，考虑下
                                current_line-=1
                        else:
                            current_line-=1
        del vulnerable_apis['code_line']
        del vulnerable_apis['blob_num_addition_parent_arr']
        vulnerdate_obj['vulnerable_apis'].append(vulnerable_apis)
        yield vulnerdate_obj
    def get_snipaste_gitlab_code(self,response):
        response_text = json.loads(response.text)['html']
        soup = BeautifulSoup(response_text, "html.parser")
        vulnerable_apis = response.meta['vulnerable_apis']
        vulnerdate_obj = response.meta['vulnerdate_obj']
        vulnerable_apis['vulnerable_apis']=[]
        print(vulnerable_apis)
        print(vulnerable_apis['code_line'])
        if(len(vulnerable_apis['code_line'])!=0):
            for item in vulnerable_apis['code_line']:
                start_line=int(item.split('-')[0])
                end_line=int(item.split('-')[1])
                current_line=end_line
                remain_modified_line_nums=0
                while current_line>0 and (current_line>=start_line or remain_modified_line_nums>0):
                    current_code_str = soup.select('#LC' + str(current_line))[0].text
                    print(current_line)
                    print(current_code_str)
                    print(str(current_line) in vulnerable_apis['blob_num_addition_parent_arr'])
                    print(current_code_str.strip() != '')
                    if(str(current_line) in vulnerable_apis['blob_num_addition_parent_arr'] and current_code_str.strip() != '' and current_code_str[0].isspace() == True):
                        #代表当前行是新增或者删除的漏洞的代码行
                        remain_modified_line_nums+=1
                        current_line -= 1
                    else:
                        if(remain_modified_line_nums>0):
                            if(len(current_code_str)>0):
                                current_code_str1 = soup.select('#LC' + str(current_line))[0].text
                                if(soup.select('#LC' + str(current_line - 1))):
                                    current_code_str2 = soup.select('#LC' + str(current_line - 1))[0].text
                                if(soup.select('#LC' + str(current_line - 2))):
                                    current_code_str3 = soup.select('#LC' + str(current_line - 2))[0].text
                                new_str = current_code_str3.rstrip() + ' ' + current_code_str2.rstrip() + ' ' + current_code_str1
                                if(current_code_str[0]=='}'):
                                    current_line-=1
                                    remain_modified_line_nums=0
                                elif(current_code_str[0]=='{' ):
                                    #从当前行往前扫描 直到扫描到（左括号
                                    current_line-=1
                                    function_name_str=''
                                    if(soup.select('#LC'+str(current_line))):
                                        while((soup.select('#LC'+str(current_line))[0].text).strip() != ''
                                        and (soup.select('#LC'+str(current_line))[0].text).strip() != '*/'
                                        # and '//' not in (soup.select('#LC'+str(current_line))[0].text)
                                        and (soup.select('#LC'+str(current_line))[0].text).strip()[0] != '#'
                                        and (soup.select('#LC'+str(current_line))[0].text).strip()[0] != '}'):
                                            function_name_str = delcommonds((soup.select('#LC' + str(current_line))[0].text).rstrip())+' '+function_name_str
                                            current_line -= 1
                                    print("-------")
                                    print(function_name_str)
                                    print("======")
                                    #去掉注释
                                    function_name_str=delcommonds(function_name_str)
                                    function_name_body_title = re.findall(
                                        r'([A-Za-z_0-9()]+\s*[\\*]*\s*[A-Za-z_0-9]+\s*\([^)]*\))',
                                        function_name_str)
                                    if(len(function_name_body_title)!=0):
                                        if(function_name_body_title[0] not in  vulnerable_apis['vulnerable_apis']):
                                            vulnerable_apis['vulnerable_apis'].append(function_name_body_title[0])
                                    remain_modified_line_nums=0
                                elif(current_code_str[0].isspace() == False and current_code_str[0] !='{' and current_code_str[0] !='#' and '{' in current_code_str):
                                    function_name_str = ''
                                    if (soup.select('#LC' + str(current_line))):
                                        while ((soup.select('#LC' + str(current_line))[0].text).strip() != ''
                                               and ' if ' not in soup.select('#LC' + str(current_line))[0].text
                                               # and ' // ' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'switch' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'case' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'else' not in soup.select('#LC' + str(current_line))[0].text
                                               and ' do' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'for' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'while' not in soup.select('#LC' + str(current_line))[0].text
                                               and (soup.select('#LC' + str(current_line))[0].text).strip() != '*/'
                                               and (soup.select('#LC' + str(current_line))[0].text).strip()[0] != '#'):
                                            function_name_str = delcommonds((soup.select('#LC' + str(current_line))[
                                                                     0].text).rstrip())+ ' ' + function_name_str
                                            current_line -= 1

                                    # 去掉注释
                                    new_str = delcommonds(new_str)
                                    print('00000')
                                    print(new_str)
                                    print('11111')
                                    function_name_body_title = re.findall(
                                        r'([A-Za-z_0-9()]+\s*[\\*]*\s*[A-Za-z_0-9]+\s*\([^)]*\))',
                                        new_str)
                                    current_line -= 2
                                    if (len(function_name_body_title) != 0):
                                        if (function_name_body_title[0] not in vulnerable_apis['vulnerable_apis']):
                                            vulnerable_apis['vulnerable_apis'].append(function_name_body_title[0])
                                        remain_modified_line_nums = 0
                                elif(current_code_str[0].isspace() == True and '{' in current_code_str and '}' not in  current_code_str and len(current_code_str.strip())!=1 and  'if' not in current_code_str
                                and  ';' not in current_code_str and  ' do' not in current_code_str  and 'case' not in current_code_str and  'switch' not in current_code_str and   'else' not in current_code_str  and  'while' not in current_code_str and 'switch' not in current_code_str and 'for' not in current_code_str):

                                    function_name_str = ''
                                    if (soup.select('#LC' + str(current_line))):
                                        while ((soup.select('#LC' + str(current_line))[0].text).strip() != ''
                                               and (soup.select('#LC' + str(current_line))[0].text).strip() != '*/'
                                               and ' if ' not in soup.select('#LC' + str(current_line))[0].text
                                               # and '//' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'if ' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'switch' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'case' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'else' not in soup.select('#LC' + str(current_line))[0].text
                                               and ' do' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'for' not in soup.select('#LC' + str(current_line))[0].text
                                               and 'while' not in soup.select('#LC' + str(current_line))[0].text
                                               and (soup.select('#LC' + str(current_line))[0].text).strip()[0] != '#'):
                                                print(' if ' not in soup.select('#LC' + str(current_line))[0].text)
                                                function_name_str = delcommonds((soup.select('#LC' + str(current_line))[
                                                                     0].text).rstrip()) + ' ' + function_name_str
                                                current_line -= 1
                                    # 去掉注释
                                    function_name_str = delcommonds(function_name_str)
                                    print("哈哈哈哈哈")
                                    print(function_name_str)
                                    print("嘿嘿嘿")
                                    if(len(function_name_str.strip()) !=0 and ' if ' not in function_name_str and  'else' not in current_code_str
                                            and  'switch' not in current_code_str and 'case' not in current_code_str
                                            and  ' do' not in current_code_str and 'for' not in function_name_str
                                            and 'while' not in function_name_str and 'switch' not in function_name_str):
                                        function_name_body_title = re.findall(
                                            r'([A-Za-z_0-9()]+\s*[\\*]*\s*[A-Za-z_0-9]+\s*\([^)]*\))',
                                            function_name_str)
                                        print('77777777777777777')
                                        if (len(function_name_body_title) != 0):
                                            if (function_name_body_title[0] not in vulnerable_apis['vulnerable_apis']):
                                                vulnerable_apis['vulnerable_apis'].append(function_name_body_title[0])
                                            remain_modified_line_nums = 0
                                else:
                                    current_line-=1
                            else:
                                current_line-=1
                        else:
                            current_line-=1
        del vulnerable_apis['code_line']
        del vulnerable_apis['blob_num_addition_parent_arr']
        vulnerdate_obj['vulnerable_apis'].append(vulnerable_apis)
        yield vulnerdate_obj
    def parse(self, response):
        html_doc = response.body
        soup = BeautifulSoup(html_doc,"html.parser")
        glsa_list = soup.select('body > div > div > div > div.table-responsive.mb-3 > table   tr')
        item='https://github.com/rdesktop/rdesktop/commit/4dca546d04321a610c1835010b5dad85163b65e1'
        vulnerdate_obj = TutorialItem()
        # 在cve页面获取信息
        vulnerdate_obj['fixed_versions_and_patch'] = []
        vulnerdate_obj['vulnerable_apis'] = []
        vulnerdate_obj['vulnerable_code_snippet'] = []
        vulnerdate_obj['program_language_of_source_code'] = ''
        vulnerdate_obj['program_language_of_library'] = ''
        yield scrapy.Request(item, callback=self.fixed_versions,
                             meta={'patch_href': item, 'vulnerdate_obj': vulnerdate_obj})
        return
        print(len(glsa_list))
        return
        for item in glsa_list[515:516]:
        # for item in glsa_list[2500:3000]:
            glsa_id = item.select('th a')[0].text

            detail_url ='https://glsa.gentoo.org/glsa/'+glsa_id
            vulnerable_library=item.select('td')[0].text.split(':')[0]
            print(detail_url)
            print(vulnerable_library)
            # 给详情页面发送请求
            yield scrapy.Request(detail_url, callback=self.get_glsa_package_detail_info,meta={'vulnerable_library':vulnerable_library},dont_filter=True)
def delcommonds(content):
    out = re.sub(r'/\*.*?\*/', '', content, flags=re.S)
    out = re.sub(r'(//.*)', '', out)
    return out
def from_current_line_find_before(response,current_line):
    function_name_str=''
    if(current_line==1 and  '/*' in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip()):
        while (response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','').strip() !='*/'):
            function_name_str=function_name_str+response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
            '\t', '')
            current_line += 1
        current_line += 1
    while ('}' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace('\t','')
           and ' if ' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and ';' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and ' if' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and 'if ' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and 'switch' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[
               0].replace('\t', '')
           and 'case' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and 'else' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and ' do' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and 'for' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and 'while' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
                '\t', '')
           and 'switch' not in response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[
               0].replace('\t', '')
    ):
        function_name_str = function_name_str+' '+response.xpath('string(//*[@id="LC' + str(current_line) + '"])').extract()[0].replace(
            '\t', '').rstrip()
        current_line +=1
    function_name_str_delete=delcommonds(function_name_str)
    return function_name_str_delete