# Struts2-AutoPwn

## Usage

```
python autopwn.py
```

## About

The `autopwn.py` will run a google search crawler with keywords definded at `crawler.conf` to find vulnerable URLs.

### `crawler.conf`

`base_url` : the basic google search url

`keyword` : e.g. site:gov ext:action

`expect_num` : expect search results to be crawlered

`http/socks` : set a HTTP/SOCKS5 proxy for the crawler

## Dependence

You need to run the following command to install requirements.

```
pip install beautifulsoup4 requests
```

If you want to use a SOCKS5 proxy, then install requests[socks] with pip.

```
pip install requests[socks]
```

## Reference

> 
> https://github.com/meibenjin/GoogleSearchCrawler
> 
> http://www.freebuf.com/sectool/129224.html
> 
