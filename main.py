#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @author YWLBTWTK
# @date 2024/3/1
import ssl
import sys
import json
import time
import requests
import urllib.parse
import urllib.request
from json import loads
from re import search, S
from loguru import logger
from random import choice
from http import cookiejar
from base64 import b64encode
from datetime import datetime
from Cryptodome.Cipher import AES
from urllib3 import disable_warnings
from apscheduler.schedulers.blocking import BlockingScheduler

logger.remove()
logger.add(sys.stderr, level="INFO")
logger.add('./logs/log.txt', level='DEBUG', encoding='utf8', enqueue=True, backtrace=True, diagnose=True, rotation="12:00")


def push_plus(content):
    resp = requests.post('https://www.pushplus.plus/send',
                         data={
                             "token": "",
                             "title": f"上班打卡结果{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                             "content": content,
                             "topic": "",
                             "template": "html"
                         })

    logger.debug(resp.json())


class SZPUInternshipCheckIn:
    def __init__(self, username, password, qdszd="广东省, 深圳市, 南山区", qdxxdz="广东省深圳市南山区西丽街道深圳职业技术大学(西丽湖园区)日新楼"):
        logger.debug(f'username:{username},password:{password},qdszd:{qdszd},qdxxdz:{qdxxdz}')
        # Disable SSL warnings
        self.qdxxdz = qdxxdz
        self.qdszd = qdszd
        disable_warnings()
        ssl._create_default_https_context = ssl._create_unverified_context

        # 参数
        self.token, self.shopName = '', ''
        self.username, self.password = username, password
        self.headers = {'Accept': 'application/json, text/plain, */*'}

    @logger.catch
    def login(self):
        class NoRedirHandler(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return fp

            http_error_301 = http_error_302

        logger.info(f'{self.username}正在登录...')
        # 登录请求
        login_url = 'https://authserver.szpu.edu.cn/authserver/login?service=' \
                    'https%3A%2F%2Fjwxt.szpu.edu.cn%2Fjwapp%2Fsys%2FxsdgsxbmMobile%2F%2Adefault%2Findex.do%23%2Fqddk'
        request = urllib.request.Request(url=login_url, method='GET')
        cookie_jar = cookiejar.CookieJar()
        time_sleep(range(2, 10))
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar), NoRedirHandler)
        html = opener.open(request).read().decode('utf-8')
        # 判断是否需要captcha
        check_url = 'https://authserver.szpu.edu.cn/authserver/checkNeedCaptcha.htl?username=' + self.username
        time_sleep(range(2, 10))
        if loads(opener.open(check_url).read().decode('utf-8'))['isNeed']:
            logger.error(f'需要图片验证码，请前往登录页面登录后重试！{login_url}')
            return
        # 获取登录参数
        logger.debug(f"{self.username}——{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}保存html内容：\n\n\n{html}\n\n\n")
        if html in 'IP被冻结':
            logger.error('IP被冻结！')
            return f'<font color="red">{self.username}无法打卡</font>，IP被冻结'
        execution = search('name="execution" value="(.*?)"', html, S).group(1)
        aes_key = search('pwdEncryptSalt" value="(.*?)"/>', html, S).group(1)[:16].encode('utf-8')
        aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
        iv = ''.join([choice(aes_chars) for _ in range(16)]).encode()
        raw = ''.join([choice(aes_chars) for _ in range(64)]) + self.password
        amount_to_pad = AES.block_size - (len(raw) % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        raw = (raw + chr(amount_to_pad) * amount_to_pad).encode()
        password_aes = b64encode(AES.new(aes_key, AES.MODE_CBC, iv).encrypt(raw))
        params = {'username': self.username, 'password': str(password_aes)[2:-1], 'captcha': '',
                  '_eventId': 'submit', 'cllt': 'userNameLogin', 'dllt': 'generalLogin', 'lt': '',
                  'execution': execution}
        # 获取重定向
        time_sleep(range(2, 10))
        result = urllib.request.Request(url=login_url, method='POST',
                                        data=urllib.parse.urlencode(params).encode(encoding='UTF-8'))
        login_url = opener.open(result).headers['Location']
        time_sleep(range(2, 10))
        login_url = opener.open(urllib.request.Request(url=login_url, method='GET')).headers['Location']
        time_sleep(range(2, 10))
        login_url_resp = opener.open(urllib.request.Request(url=login_url, method='GET'))
        login_url = login_url_resp.headers['Location']
        time_sleep(range(2, 10))
        opener.open(urllib.request.Request(url='https://jwxt.szpu.edu.cn/jwapp/sys/xsdgsxbmMobile/*default/index.do', method='GET'))
        time_sleep(range(2, 10))
        opener.open(urllib.request.Request(url='https://jwxt.szpu.edu.cn/jwapp/sys/mobilepub/res/sentry/xsdgsxbmMobile.do', method='GET'))
        time_sleep(range(2, 10))
        opener.open(urllib.request.Request(url='https://jwxt.szpu.edu.cn/jwapp/sys/mobilepub/getAppConfig/xsdgsxbmMobile.do', method='POST'))
        cookies = {}
        for cookie in cookie_jar:
            cookies[cookie.name] = cookie.value
        cxjhxs_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://jwxt.szpu.edu.cn',
            'Referer': 'https://jwxt.szpu.edu.cn/jwapp/sys/xsdgsxbmMobile/*default/index.do',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        data = {
            'XH': self.username,
            'SXZT': 'sxz',
        }

        time_sleep(range(2, 10))
        cxjhxs_response = requests.post(
            'https://jwxt.szpu.edu.cn/jwapp/sys/xsdgsxbmMobile/modules/qddk/cxjhxs.do',
            cookies=cookies,
            headers=cxjhxs_headers,
            data=data,
        )
        logger.debug(cxjhxs_response.text)
        wid = cxjhxs_response.json()['datas']['cxjhxs']['WID']
        logger.debug(wid)
        bcxsqdxx_headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://jwxt.szpu.edu.cn',
            'Pragma': 'no-cache',
            'Referer': 'https://jwxt.szpu.edu.cn/jwapp/sys/xsdgsxbmMobile/*default/index.do?ticket=ST-220119-P4J1WHcoYktgHZnYlxU66lrGXlchost-192-168-1-198',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Chromium";v="117", "Not;A=Brand";v="8"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }
        params = {'param': [
            {
                "JHXSWID": wid,
                "XH": self.username,
                "QDSJ": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "QDSZD": self.qdszd,
                "QDXXDZ": self.qdxxdz,
                "BY1": "qddk",
                "WID": ""
            }]}
        logger.debug(params)
        time_sleep(range(2, 10))
        bcxsqdxx_response = requests.post(
            'https://jwxt.szpu.edu.cn/jwapp/sys/xsdgsxbmMobile/modules/qddk/bcxsqdxx.do',
            cookies=cookies,
            headers=bcxsqdxx_headers,
            data=urllib.parse.urlencode(params).encode(encoding='UTF-8')
        )
        logger.debug(bcxsqdxx_response.text)
        bcxsqdxx_response_json = bcxsqdxx_response.json()
        logger.debug(bcxsqdxx_response_json)
        is_flag = bcxsqdxx_response_json['code']
        if is_flag == '0':
            logger.info(f'{self.username}打卡成功')
            return f'<font color="green">{self.username}打卡成功</font>'
        else:
            logger.error(f'{self.username}打卡失败')
            return f'<font color="red">{self.username}打卡失败</font>'


def time_sleep(range_list):
    sleep_sec = choice(range_list)
    logger.info(f'开始休眠！休眠：{sleep_sec}秒')
    time.sleep(sleep_sec)
    logger.info('休眠结束！')


def main():
    logger.info('定时已到——打卡，启动！')
    with open('userdata.json', 'r', encoding='utf-8') as f:
        data = json.loads(f.read())
    txt = ''
    for i in data:
        username = i['username']
        password = i['password']
        try:
            return_str = SZPUInternshipCheckIn(username, password).login()
        except:
            return_str = f'<font color="red">{username}无法打卡</font>'
        if return_str is None:
            return_str = f'<font color="red">{username}无法打卡</font>'
        txt += return_str + '\n'
        time_sleep(range(300, 500))
    push_plus(txt)
    logger.info('打卡完毕！')


if __name__ == '__main__':
    logger.info(f"******定时器，启动！******")
    scheduler = BlockingScheduler()
    scheduler.add_job(main, 'cron', day_of_week='0-4', hour=7, minute=50)
    scheduler.start()
    logger.info(f"******定时器，关闭！******")
