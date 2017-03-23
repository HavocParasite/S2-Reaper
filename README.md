# Struts2-AutoPwn

## Usage

```
python autopwn.py
```

## About

This project including two parts. First is `autopwn.py` , which will run a google search crawler with keywords definded at `crawler.conf` to find vulnerable URLs. Second is `exploit.py` , witch will run exploit on those URLS recorded by `autopwn.py`.

I will integrate these two parts together later.

### `crawler.conf`

`base_url` : the basic google search url

`keyword` : e.g. site:gov ext:action

`expect_num` : expect search results to be crawlered

`http/socks5 proxy` : set a proxy for the crawler

### `cmd.txt`

After `autopwn.py` have recorded all vulnerable URLs in `vulnerable.txt`, you can set commands that you want to run on remote hosts in `cmd.txt`. Each line will be an independent command to execute. Finally, run `python exploit.py` and have fun!

## Reference

> 
> https://github.com/meibenjin/GoogleSearchCrawler
> 
> http://www.freebuf.com/sectool/129224.html
> 
