from bs4 import BeautifulSoup

def get_joomla_login_form(session, login_url):
    from bs4 import BeautifulSoup
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, "html.parser")
    try:
        token = soup.findAll("input", {"type": "hidden"})[3]['name']
    except: 
        token = "token"
    LOGIN_INFO = {
        "username": "admin",
        "passwd": "admin",
        "option": "com_login",
        "task": "login",
        "return": "aW5kZXgucGhw"
    }
    LOGIN_INFO[token] = "1"
    return LOGIN_INFO

def get_phoenixcart_form(session, login_url):
    from bs4 import BeautifulSoup
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, "html.parser")
    token = soup.findAll("input", {"type": "hidden"})[0]['value']
    LOGIN_INFO = {
        "formid": token,
        "username": "admin",
        "password": "admin"
    }
    return LOGIN_INFO

def get_dvwa_login_form(session, login_url):
    from bs4 import BeautifulSoup
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, "html.parser")
    token = soup.findAll("input", {"type": "hidden"})[0]['value']
    LOGIN_INFO = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }
    #LOGIN_INFO[token] = "1"
    return LOGIN_INFO

def get_phpwcms_login_form(session, login_url):
    from bs4 import BeautifulSoup
    response = session.get(login_url)
    print(response.text.split('name="logintoken" value="')[1].split('"')[0])
    soup = BeautifulSoup(response.text, "html.parser")
    #print( soup.findAll("input", {"type": "hidden"}))
    token = response.text.split('name="logintoken" value="')[1].split('"')[0]
    LOGIN_INFO = {
        "json": "1",
        "customlang": "",
        "md5pass": "21232f297a57a5a743894a0e4a801fc3",
        "ref_url": "",
        "logintoken": token,
        "form_aktion": "login",
        "form_loginname": "admin",
        "form_password": "",
        "form_lang": "en",
        "submit_form": "Login"
    } 
    #LOGIN_INFO[token] = "1"
    return LOGIN_INFO

def get_flaskbb_login_form(session, login_url):
    from bs4 import BeautifulSoup
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, "html.parser")
    try:
        token = soup.findAll("input", {"type": "hidden"})[0]['value']
    except:
        token = "token"
    LOGIN_INFO = {
            "recaptcha": "",
            "csrf_token": token,
            "login": "admin",
            "password": "admin",
            "submit":"Login"
    }  
    #LOGIN_INFO[token] = "1"
    return LOGIN_INFO


def get_phpbb_login_form(session, login_url):
    from bs4 import BeautifulSoup
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, "html.parser")
    creation_time = soup.findAll("input", {"type": "hidden"})[1]['value']
    form_token = soup.findAll("input", {"type": "hidden"})[2]['value']
    sid = soup.findAll("input", {"type": "hidden"})[3]['value']                         
    LOGIN_INFO = {
        "username": "admin",
        "password": "adminadmin",
        "redirect": "./ucp.php?mode=login&redirect=index.php",
        "creation_time": creation_time,
        "form_token": form_token,
        "sid": sid ,
        "redirect": "index.php",
        "login": "Login"
    }  
    
    #LOGIN_INFO[token] = "1"
    return LOGIN_INFO


def get_nextcloud_login_form(session, login_url):
    from bs4 import BeautifulSoup
    response = session.get(login_url)
    
    soup = BeautifulSoup(response.text, "html.parser")
    print(soup.findAll("head")[0]['data-requesttoken'])
    #print( soup.findAll("input", {"type": "hidden"}))
    token = soup.findAll("head")[0]['data-requesttoken']
    LOGIN_INFO = {
            "user": "admin",
            "password": "admin",
            "timezone": "Asia/Seoul",
            "timezone_offset": "9",
            "requesttoken": token
    }
    #LOGIN_INFO[token] = "1"
    return LOGIN_INFO

def login_credentials(session, input_url):

    if "doctor" in input_url and "hms" not in input_url:
        base_url = input_url.split("doctor-1")[0]
        start_url = base_url + "doctor-1/doctor/doctordashboard.php"
        login_url = base_url + "doctor-1/adminlogin.php"
        LOGIN_INFO = {
            "doctorId": "123",
            "password": "123",
            "login": ""
        }

    elif "joomla" in input_url:
        base_url = input_url.split("joomla-3.8.8")[0]
        
        start_url = base_url + "joomla-3.8.8/administrator/"   
        login_url = base_url + "joomla-3.8.8/administrator/index.php"

        LOGIN_INFO = get_joomla_login_form(session, login_url)
    
        
    elif "hms" in input_url:
        if "admin" in input_url:
            base_url = input_url.split("hms-4")[0]
            start_url = base_url + "hms-4/hospital/hms/admin/dashboard.php"
            login_url = base_url + "hms-4/hospital/hms/admin/"

            LOGIN_INFO = {
                "username": "admin",
                "password": "Test@12345",
                "submit": "",
                "submit": ""
            }

       
    elif ":4000" in input_url:
        # nodegoat
        base_url = input_url.split(":4000")[0] + ":4000"
        start_url = base_url + "/dashboard"
        login_url =  base_url + "/login"

        LOGIN_INFO = {
            "userName": "zelda",
            "password": "zelda",
            "_csrf": ""
        } 
    
    
    elif "8080" in input_url:
        # wackopicko
        base_url = input_url.split(":1001")[0] + ":1001"
        start_url = base_url + "/"
        login_url = base_url + "/users/login.php"
        LOGIN_INFO = {
            "username": "scanner1",
            "password": "scanner1"
        } 
    
    elif "1005" in input_url:
        # juice shop
        base_url = input_url
        start_url = base_url
        login_url = base_url + "#/login"
        LOGIN_INFO = {
            "email": "zelda@zelda.com",
            "password": "zelda"
        }
    elif ":1004" in input_url:
        # dvna
        base_url = input_url.split(":1004")[0] + ":1004"
        start_url = base_url + "/app"
        login_url = base_url + "/login"

        LOGIN_INFO = {
            "username": "zelda",
            "password": "zelda"
        } 
   
    elif "1006" in input_url:
        #WebGoat 
        base_url = input_url.split(":1006")[0] + ":1006"
        start_url = base_url + "/WebGoat/start.mvc?username=zeldazelda#lesson/WebWolfIntroduction.lesson"
        login_url =  base_url + "/WebGoat/login"
        LOGIN_INFO = {
            "username": "zeldazelda",
            "password": "zeldazelda"
        } 
    elif "openemr" in input_url:
        base_url = input_url.split("openemr-5_0_1_7")[0]
        start_url = base_url + "openemr-5_0_1_7"
        login_url = base_url + "openemr-5_0_1_7/interface/main/main_screen.php?auth=login&site=default"
        LOGIN_INFO = {
            "new_login_session_management": "1",
            "authProvider": "Default",
            "authUser": "admin",
            "clearPass": "admin",
            "languageChoice": "1"
        } 
    elif "PhoenixCart" in input_url:
        base_url = input_url.split("PhoenixCart-1.0.8.20")[0]
        start_url = base_url + "PhoenixCart-1.0.8.20/admin/index.php"
        login_url = base_url + "PhoenixCart-1.0.8.20/admin/login.php?action=process"
        LOGIN_INFO = get_phoenixcart_form(session, login_url)
        
    elif "lodel" in input_url:
        base_url = input_url.split("lodel-1.0.5")[0] 
        start_url = base_url + "lodel-1.0.5/lodeladmin/"
        login_url = base_url + "lodel-1.0.5/lodeladmin/login.php"
        LOGIN_INFO = {
            "url_retour": "/lodel-1.0.5/lodeladmin/",
            "login": "admin",
            "passwd": "Ui4oochaacoun2a"
        } 
        
    elif "phpwcms" in input_url:
        base_url = input_url.split("phpwcms-1.9.26")[0]
        start_url = base_url + "phpwcms-1.9.26/phpwcms.php"
        login_url = base_url + "phpwcms-1.9.26/login.php"
        LOGIN_INFO = get_phpwcms_login_form(session, login_url)

    
    elif ":1222" in input_url:
        base_url = input_url.split(":1222")[0] + ":1222"
        start_url = base_url +"/apps/dashboard/"
        login_url = base_url +"/login?clear=1"
        LOGIN_INFO = get_nextcloud_login_form(session, login_url)

    elif "5000" in input_url: 
        base_url = input_url.split(":5000")[0] + ":5000"
        start_url = base_url + "/"
        login_url = base_url + "/auth/login"
        LOGIN_INFO = get_flaskbb_login_form(session, login_url)

    elif "9000" in input_url:
        base_url = input_url.split(":9000")[0] + ":9000"
        start_url = base_url + "/"
        login_url = base_url + "/"
        LOGIN_INFO = {}

    else:
        raise Exception("No login info available for this application.")
    
    return login_url, start_url, LOGIN_INFO 

if __name__ == '__main__':
    import requests
    session = requests.Session()
    _, _, login = login_credentials(session, "wordpress")
    print(login)