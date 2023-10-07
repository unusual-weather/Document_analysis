from flask import Flask,request
import requests
from models.binary_classifier import binary_test
from VT.VT import vt_test

app = Flask(__name__)

# @app.route('/http=<http>&url=<url>',methods=['GET'])
# def main_page(http,url):
#     if "http" not in http:
#         http = "http"
#     domain = f"{http}://{url}"
#     res = requests.get(domain)
    
#     if "text/html;" == str(res.headers['Content-Type']).split()[0]:
#         res = binary_test(domain,res)
#     elif res.status_code!=200:
#         res = "the server is down"
#     else:
#         res = vt_test(domain) #추후 파일로 수정하는 방안 고안해야할 듯
#     print(domain)
#     res = vt_test(domain)
#     return str(res)


@app.route('/',methods=['POST'])
def post_page():
    domain = request.form['target']
    print(domain)
    res = requests.get(domain)
    if "text/html;" == str(res.headers['Content-Type']).split()[0]:
        res = binary_test(domain,res)
    elif res.status_code!=200:
        res = "the server is down"
    else:
        res = vt_test(domain) #추후 파일로 수정하는 방안 고안해야할 듯
        
    res = vt_test(domain)
    print(res)
    return str(res)
    
    
    
app.run(host="127.0.0.1",port=8000)