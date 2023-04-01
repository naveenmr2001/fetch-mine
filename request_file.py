import requests
from bs4 import BeautifulSoup

def logo(url):
    response = requests.get(url)
    html_content = response.content

    soup = BeautifulSoup(html_content, 'html.parser')

    logo_tag = soup.find('link', rel='shortcut icon') or soup.find('link', rel='icon') or soup.find('img', alt='logo')

    if logo_tag is not None:
        logo_url = logo_tag['href'] if 'href' in logo_tag.attrs else logo_tag['src']
        if not logo_url.startswith('http'):
            logo_url = url + logo_url if logo_url.startswith('/') else url + '/' + logo_url
        return logo_url
    else:
        return 'https://icons.saymine.com/ziz1ThbXpJbt'

def website_name(url):
    website_name = url.split('//')[-1].split('/')[0].split('.')[-2]
    return website_name
