import scrapy


class TtmjspiderspiderSpider(scrapy.Spider):
    name = 'TtmjspiderSpider'
    allowed_domains = ['www.baidu.com']
    start_urls = ['http://www.baidu.com/']

    def parse(self, response):
        pass
