# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class TutorialItem(scrapy.Item):
    # define the fields for your item here like:
    identifiers = scrapy.Field()
    vulnerable_versions = scrapy.Field()
    unaffected_versions = scrapy.Field()
    affected_versions = scrapy.Field()
    cvss = scrapy.Field()
    cwes = scrapy.Field()
    vulnerable_library = scrapy.Field()
    fixed_versions_and_patch = scrapy.Field()
    vulnerable_apis = scrapy.Field()
    vulnerable_code_snippet = scrapy.Field()
    program_language_of_source_code = scrapy.Field()
    program_language_of_library = scrapy.Field()
    file_paths = scrapy.Field()
    #文件
    file_urls = scrapy.Field()
    files = scrapy.Field()
    pass
