import requests
import string
import random
import json
import uuid
import os
import webbrowser
from subprocess import CalledProcessError, check_output
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import win32security


endpoint = "https://api.authspire.com/v1"

class User:
    def __init__(self):
        self.username = None
        self.email = None
        self.ip = None
        self.expires = None
        self.hwid = None
        self.last_login = None
        self.created_at = None
        self.variable = None
        self.level = None


class Application:
    def __init__(self):
        self.application_status = None
        self.application_name = None
        self.user_count = None
        self.application_version = None
        self.update_url = None
        self.application_hash = None

class api:

    application = Application()
    user = User()
    variables = {}
    initialized = False

    def __init__(self, app_name, userid, secret, currentVersion, publicKey):
        self.app_name = app_name
        self.userid = userid
        self.secret = secret
        self.currentVersion = currentVersion
        self.publicKey = publicKey
        self.init()

    def init(self):
        self.key = util.randomStr(32)
        self.iv = util.randomStr(16)
        
        data = {
            "action": b64encode(bytes("app_info", "utf-8")),
            "userid": b64encode(bytes(self.userid, "utf-8")),
            "app_name": b64encode(bytes(self.app_name, "utf-8")),
            "secret": encryption.aes_encrypt(self.secret, self.key, self.iv),
            "version": encryption.aes_encrypt(self.currentVersion, self.key, self.iv),
            "hash": "", #Encryption.AESEncrypt(self.your_hash, self.key, self.iv), to use with your hash
            "key": encryption.rsa_encrypt(self.key, self.publicKey),
            "iv": encryption.rsa_encrypt(self.iv, self.publicKey)
        }
        response_enc = self.post(data)
        response = json.loads(response_enc)

        if response["status"] == "success":
            api.application.application_status = encryption.aes_decrypt(response["application_status"], self.key, self.iv)
            api.application.application_hash = encryption.aes_decrypt(response["application_hash"], self.key, self.iv)
            api.application.application_name = encryption.aes_decrypt(response["application_name"], self.key, self.iv)
            api.application.application_version = encryption.aes_decrypt(response["application_version"], self.key, self.iv)
            api.application.update_url = encryption.aes_decrypt(response["update_url"], self.key, self.iv)
            api.application.user_count = encryption.aes_decrypt(response["user_count"], self.key, self.iv)
            api.initialized = True
        elif response["status"] == "update_available":
            api.application.update_url = encryption.aes_decrypt(response["update_url"], self.key, self.iv)
            api.application.application_version = encryption.aes_decrypt(response["application_version"], self.key, self.iv)
            self.update_application(api.application.update_url, api.application.application_version)
            return False
        elif response["status"] == "invalid_hash":
            self.error(ApplicationManipulated)
        elif response["status"] == "invalid_app":
            self.error(InvalidApplication)
        elif response["status"] == "paused":
            self.error(ApplicationPaused)
        elif response["status"] == "locked":
            self.error(ApplicationDisabled)
        return True


    def login(self, username, password):

        if not api.initialized:
            self.error(NotInitialized)

        self.key = util.randomStr(32)
        self.iv = util.randomStr(16)
        
        data = {
            "action": b64encode(bytes("login", "utf-8")),
            "userid": b64encode(bytes(self.userid, "utf-8")),
            "app_name": b64encode(bytes(self.app_name, "utf-8")),
            "secret": encryption.aes_encrypt(self.secret, self.key, self.iv),
            "username": encryption.aes_encrypt(username, self.key, self.iv),
            "password": encryption.aes_encrypt(password, self.key, self.iv),
            "hwid": encryption.aes_encrypt(util.get_hwid(), self.key, self.iv),
            "key": encryption.rsa_encrypt(self.key, self.publicKey),
            "iv": encryption.rsa_encrypt(self.iv, self.publicKey)
        }
        response_enc = self.post(data)
        response = json.loads(response_enc)


        if response["status"] == "ok":
            api.user.username = encryption.aes_decrypt(response["username"], self.key, self.iv)
            api.user.email = encryption.aes_decrypt(response["email"], self.key, self.iv)
            api.user.ip = encryption.aes_decrypt(response["ip"], self.key, self.iv)
            api.user.expires = encryption.aes_decrypt(response["expires"], self.key, self.iv)
            api.user.hwid = encryption.aes_decrypt(response["hwid"], self.key, self.iv)
            api.user.last_login = encryption.aes_decrypt(response["last_login"], self.key, self.iv)
            api.user.created_at = encryption.aes_decrypt(response["created_at"], self.key, self.iv)
            api.user.variable = encryption.aes_decrypt(response["variable"], self.key, self.iv)
            api.user.level = encryption.aes_decrypt(response["level"], self.key, self.iv)

            app_variables = encryption.aes_decrypt(response["app_variables"], self.key, self.iv)
            for app_variable in app_variables.split(";"):
                app_variable_split = app_variable.split(":")
                try:
                    api.variables[app_variable_split[0]] = app_variable_split[1]
                except:
                    pass
            return True
        elif response["status"] == "invalid_user":
            self.error(InvalidUserCredentials)
        elif response["status"] == "invalid_details":
            self.error(InvalidUserCredentials)
        elif response["status"] == "license_expired":
            self.error(UserLicenseExpired)
        elif response["status"] == "invalid_hwid":
            self.error(UserLicenseTaken)
        elif response["status"] == "banned":
            self.error(UserBanned)
        elif response["status"] == "blacklisted":
            self.error(UserBlacklisted)
        elif response["status"] == "vpn_blocked":
            self.error(VPNBlocked)
        else:
            return False


    
    def register(self, username, password, license, email):

        if not api.initialized:
            self.error(NotInitialized)

        self.key = util.randomStr(32)
        self.iv = util.randomStr(16)
        
        data = {
            "action": b64encode(bytes("register", "utf-8")),
            "userid": b64encode(bytes(self.userid, "utf-8")),
            "app_name": b64encode(bytes(self.app_name, "utf-8")),
            "secret": encryption.aes_encrypt(self.secret, self.key, self.iv),
            "username": encryption.aes_encrypt(username, self.key, self.iv),
            "password": encryption.aes_encrypt(password, self.key, self.iv),
            "license": encryption.aes_encrypt(license, self.key, self.iv),
            "email": encryption.aes_encrypt(email, self.key, self.iv),
            "hwid": encryption.aes_encrypt(util.get_hwid(), self.key, self.iv),
            "key": encryption.rsa_encrypt(self.key, self.publicKey),
            "iv": encryption.rsa_encrypt(self.iv, self.publicKey)
        }
        response_enc = self.post(data)
        response = json.loads(response_enc)


        if response["status"] == "user_added":
            return True
        elif response["status"] == "user_limit_reached":
            self.error(UserLimitReached)
        elif response["status"] == "invalid_details":
            self.error(RegisterInvalidDetails)
        elif response["status"] == "email_taken":
            self.error(RegisterEmailTaken)
        elif response["status"] == "invalid_license":
            self.error(RegisterInvalidLicense)
        elif response["status"] == "user_already_exists":
            self.error(UserExists)
        elif response["status"] == "blacklisted":
            self.error(UserBlacklisted)
        elif response["status"] == "vpn_blocked":
            self.error(VPNBlocked)
        else:
            return False


    def license(self, license):

        if not api.initialized:
            self.error(NotInitialized)

        self.key = util.randomStr(32)
        self.iv = util.randomStr(16)
        
        data = {
            "action": b64encode(bytes("license", "utf-8")),
            "userid": b64encode(bytes(self.userid, "utf-8")),
            "app_name": b64encode(bytes(self.app_name, "utf-8")),
            "secret": encryption.aes_encrypt(self.secret, self.key, self.iv),
            "license": encryption.aes_encrypt(license, self.key, self.iv),
            "hwid": encryption.aes_encrypt(util.get_hwid(), self.key, self.iv),
            "key": encryption.rsa_encrypt(self.key, self.publicKey),
            "iv": encryption.rsa_encrypt(self.iv, self.publicKey)
        }
        response_enc = self.post(data)
        response = json.loads(response_enc)


        if response["status"] == "ok":
            api.user.username = encryption.aes_decrypt(response["username"], self.key, self.iv)
            api.user.email = encryption.aes_decrypt(response["email"], self.key, self.iv)
            api.user.ip = encryption.aes_decrypt(response["ip"], self.key, self.iv)
            api.user.expires = encryption.aes_decrypt(response["expires"], self.key, self.iv)
            api.user.hwid = encryption.aes_decrypt(response["hwid"], self.key, self.iv)
            api.user.last_login = encryption.aes_decrypt(response["last_login"], self.key, self.iv)
            api.user.created_at = encryption.aes_decrypt(response["created_at"], self.key, self.iv)
            api.user.variable = encryption.aes_decrypt(response["variable"], self.key, self.iv)
            api.user.level = encryption.aes_decrypt(response["level"], self.key, self.iv)

            app_variables = encryption.aes_decrypt(response["app_variables"], self.key, self.iv)
            for app_variable in app_variables.split(";"):
                app_variable_split = app_variable.split(":")
                try:
                    api.variables[app_variable_split[0]] = app_variable_split[1]
                except:
                    pass
            return True
        elif response["status"] == "invalid_user":
            self.error(InvalidUserCredentials)
        elif response["status"] == "user_limit_reached":
            self.error(UserLimitReached)
        elif response["status"] == "invalid_license":
            self.error(RegisterInvalidLicense)
        elif response["status"] == "license_expired":
            self.error(UserLicenseExpired)
        elif response["status"] == "invalid_hwid":
            self.error(UserLicenseTaken)
        elif response["status"] == "banned":
            self.error(UserBanned)
        elif response["status"] == "license_taken":
            self.error(UserLicenseTaken)
        elif response["status"] == "blacklisted":
            self.error(UserBlacklisted)
        elif response["status"] == "vpn_blocked":
            self.error(VPNBlocked)
        else:
            return False


    def add_log(self, username, action):

        if not api.initialized:
            self.error(NotInitialized)

        self.key = util.randomStr(32)
        self.iv = util.randomStr(16)
        
        data = {
            "action": b64encode(bytes("log", "utf-8")),
            "userid": b64encode(bytes(self.userid, "utf-8")),
            "app_name": b64encode(bytes(self.app_name, "utf-8")),
            "secret": encryption.aes_encrypt(self.secret, self.key, self.iv),
            "username": encryption.aes_encrypt(username, self.key, self.iv),
            "user_action": encryption.aes_encrypt(action, self.key, self.iv),
            "key": encryption.rsa_encrypt(self.key, self.publicKey),
            "iv": encryption.rsa_encrypt(self.iv, self.publicKey)
        }
        response_enc = self.post(data)
        response = json.loads(response_enc)

        if response["status"] == "log_added":
            return
        elif response["status"] == "failed":
            self.error(FailedToAddLog)
        elif response["status"] == "invalid_log_info":
            self.error(InvalidLogInfo)
        elif response["status"] == "log_limit_reached":
            self.error(LogLimitReached)

    def get_variable(self, secret):

        if not api.initialized:
            self.error(NotInitialized)


        try:
            return api.variables.get(secret)
        except:
            pass


    def error(self, msg):
        print(msg)
        exit(-1)

    def post(self, data):
        try:
            rq = requests.post(endpoint, data=data, timeout=30)
            return rq.text
        except requests.exceptions.Timeout:
            print("server not responding")

    def update_application(self, url, version):
        if os.name != 'nt':
            return

        msg = f"Update {version} available!"

        try:
            check_output(["powershell.exe", f"""
    Add-Type -AssemblyName PresentationCore,PresentationFramework;
    [System.Windows.MessageBox]::Show('{msg}');
    """])
        except CalledProcessError as e:
            print(e)

       
        try:
            webbrowser.open(url)
            exit(0)
        except Exception as e:
            print(e)
            exit(0)

class util:
    def get_hwid():
        winuser = os.getlogin() # Recommended to use a more unique way of getting the hwid
        sid = win32security.LookupAccountName(None, winuser)[0] 
        hwid = win32security.ConvertSidToStringSid(sid)
        return hwid

    def randomStr(length):
        rndStr = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
        return str(rndStr)
    
class encryption:
    def aes_encrypt(data, key, iv):
        input_bytes = bytes(data, 'utf-8')
        key_bytes = bytes(key, 'utf-8')
        iv_bytes = bytes(iv, 'utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        enc = cipher.encrypt(pad(input_bytes, AES.block_size))
        return b64encode(enc)

    def aes_decrypt(data, key, iv):
        input_bytes = b64decode(data)
        key_bytes = bytes(key, 'utf-8')
        iv_bytes = bytes(iv, 'utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        enc = cipher.decrypt(input_bytes)
        dec = unpad(enc, AES.block_size)
        return dec.decode('utf-8')

    def rsa_encrypt(data, public_key):
        key = RSA.importKey(b64decode(public_key))
        cipher = PKCS1_v1_5.new(key)
        ciphertext = cipher.encrypt(bytes(data, 'utf-8'))
        return b64encode(ciphertext)


ServerOffline = "Server is currently not responding, try again later!"
RegisterInvalidLicense = "The license you entered is invalid or already taken!"
RegisterInvalidDetails = "You entered an invalid username or email!"
RegisterUsernameTaken = "This username is already taken!"
RegisterEmailTaken = "This email is already taken!"
UserExists = "A user with this username already exists!"
UserLicenseTaken = "This license is already binded to another machine!"
UserLicenseExpired = "Your license has expired!"
UserBanned = "You have been banned for violating the TOS!"
UserBlacklisted = "Your IP/HWID has been blacklisted!"
VPNBlocked = "You cannot use a vpn with our service! Please disable it."
InvalidUser = "User doesn't exist!"
InvalidUserCredentials = "Username or password doesn't match!"
InvalidLoginInfo = "Invalid login information!"
InvalidLogInfo = "Invalid log information!"
LogLimitReached = "You can only add a maximum of 50 logs as a free user, upgrade to premium to enjoy no log limits!"
UserLimitReached = "You can only add a maximum of 30 users as a free user, upgrade to premium to enjoy no user limits!"
FailedToAddLog = "Failed to add log, contact the provider!"
InvalidApplication = "Application could not be initialized, please check your secret and userid."
ApplicationPaused = "This application is currently under construction, please try again later!"
NotInitialized = "Please initialize your application first!"
NotLoggedIn = "Please log into your application first!"
ApplicationDisabled = "Application has been disabled by the provider."
ApplicationManipulated = "File corrupted! This program has been manipulated or cracked. This file won't work anymore."
