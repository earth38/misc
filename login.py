import requests
from bs4 import BeautifulSoup

# requests.Sessionインスタンスを作成して、
s = requests.session()
r =  s.get('http://localhost')

#hiddenパラメータの取得
soup = BeautifulSoup(r.text, "html.parser")
token = soup.select_one('input[name="username"]')

# HTTPのパラメータを表すdictを渡す
data = {
    'username': 'name',
    'password': 'pass',
    'token': token.attrs["value"],
}

r =  s.post('http://localhost',data=data)

print(r.text)
