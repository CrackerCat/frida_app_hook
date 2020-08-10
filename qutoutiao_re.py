


import json
import requests
from urllib.parse import quote,unquote
key = "lang92"
params = "OSVersion=6.0.1&abCoinTask=0.0&deviceCode=867686023840729&device_code=867686023840729&distinct_id=534de2e7cf5b4d23&dtu=188201&guid=8f656371630655f06e640945987.03049826&h5_zip_version=1007&id_version=1000&is_pure=0&keyword={0}&keywordSource=history&lat=40.091071&limit=20.0&lon=116.345996&network=wifi&oaid=&page=1&searchSource=0.0&tabCode=3&time=1594815625792&tk=ACF4Ucq4QaBoLiOzWWzlrceFkjFxVjivAy00NzUxNDk1MDg5NTIyNQ&token=bf120PJ1OlRfaDBnUkqlUFHHRSMkpXwWbeUQGvBF66IkFMloTFxu5zAVIgxdBDMWgzU3-bm49vq97GHnDQ&traceId=e43ce4fbd41e1d17b3a5a18c82063bf6&tuid=eFHKuEGgaC4js1ls5a3HhQ&uuid=13fa2dd2d7dc48ab81319805028fd96a&version=30985000&versionName=3.9.85.000.0702.1633"
url = "https://api.1sapp.com/search/searchContentNew?"
params_url = params.format(quote(key))
print(params_url)
sekiro_url = "http://123.57.36.150:11001/asyncInvoke?group=contact&action=qutoutiao&phone={0}".format(quote(params_url))
response = requests.get(sekiro_url)
rj = json.loads(response.text)
rjj = json.loads(rj["data"])
print(rjj["data"])


new_url = url+params.format(quote(quote(key)))+"&sign="+rjj["data"]
print(new_url)
response = requests.get(url=new_url, verify=False)
print(response.text)

"""
C2564d.m8799c(this, C2573h.C2574a.m8837b((C0466c) new C12114e()).mo10244a(NameValueUtils.init().append(RedOrCoiConstants.KEY_ID, this.f5572X).append("member_id", this.f5573Y).append("token", Modules.account().getUser(C1378b.m4916a()).getToken()).build()).mo10238a((C2578i) new C2578i() {
OSVersion=6.0.1&deviceCode=867686023840729&device_code=867686023840729&distinct_id=534de2e7cf5b4d23&dtu=188201&env=qukan_prod&guid=8f656371630655f06e640945987.03049826&id=868834&is_pure=0&lat=40.091066&lon=116.345995&member_id=450734479&network=wifi&oaid=&time=1594967766128&tk=ACF4Ucq4QaBoLiOzWWzlrceFkjFxVjivAy00NzUxNDk1MDg5NTIyNQ&token=bf120PJ1OlRfaDBnUkqlUFHHRSMkpXwWbeUQGvBF66IkFMloTFxu5zAVIgxdBDMWgzU3-bm49vq97GHnDQ&traceId=0e9eab2ac33718244d432c5a03639692&tuid=eFHKuEGgaC4js1ls5a3HhQ&uuid=13fa2dd2d7dc48ab81319805028fd96a&version=30985000&versionName=3.9.85.000.0702.1633
6846962b058a4df8acd5517d60999452
"""

