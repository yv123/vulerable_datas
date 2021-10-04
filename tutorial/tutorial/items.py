# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class TutorialItem(scrapy.Item):
    # define the fields for your item here like:
    glsa_id = scrapy.Field()
    identifiers = scrapy.Field()
    vulnerable_versions = scrapy.Field()
    cvss = scrapy.Field()
    vulnerable_library = scrapy.Field()
    pass
