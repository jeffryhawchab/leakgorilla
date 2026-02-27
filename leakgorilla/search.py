"""Simple search engine seeder using dorks to produce seed URLs.

This is best-effort scraping of search engines to produce initial targets.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time


def load_dorks(path='dorks.conf'):
    dorks = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                dorks.append(line)
    except FileNotFoundError:
        return []
    return dorks


def query_searx(query, max_results=5):
    results = []
    try:
        url = f'https://searx.org/search?q={requests.utils.requote_uri(query)}&categories=general'
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.select('a.result__url')[:max_results]:
                href = a.get('href')
                if href:
                    results.append(href)
    except:
        pass
    return results


def query_duckduckgo(query, max_results=5):
    results = []
    try:
        url = f'https://html.duckduckgo.com/html?q={requests.utils.requote_uri(query)}'
        r = requests.post(url, data={'q': query}, timeout=6)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.find_all('a', {'class': 'result__a'})[:max_results]:
                href = a.get('href')
                if href:
                    results.append(href)
    except:
        pass
    return results


def query_yandex(query, max_results=5):
    results = []
    try:
        url = f'https://yandex.com/search/?text={requests.utils.requote_uri(query)}'
        r = requests.get(url, timeout=6)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.select('a.link')[:max_results]:
                href = a.get('href')
                if href:
                    results.append(href)
    except:
        pass
    return results


def seed_urls_from_search(dorks_file='dorks.conf', engines=None, max_per=5):
    if engines is None:
        engines = ['searx', 'duckduckgo', 'yandex']
    dorks = load_dorks(dorks_file)
    seeds = []
    for d in dorks:
        for eng in engines:
            try:
                if eng == 'searx':
                    res = query_searx(d, max_results=max_per)
                elif eng == 'duckduckgo':
                    res = query_duckduckgo(d, max_results=max_per)
                elif eng == 'yandex':
                    res = query_yandex(d, max_results=max_per)
                else:
                    res = []
                for r in res:
                    if r not in seeds:
                        seeds.append(r)
                time.sleep(1)
            except:
                continue
    return seeds
