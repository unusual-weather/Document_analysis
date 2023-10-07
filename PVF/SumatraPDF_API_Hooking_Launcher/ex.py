import os, psutil, ctypes, threading
import time, sys, struct
from ctypes import wintypes, windll
import requests
from urllib import parse

urls = {
    
}


def VirtualAlloc(size):
    global hProcess
    
    ctypes.windll.kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    return ctypes.windll.kernel32.VirtualAllocEx(hProcess, None, size, 0x3000, 0x40)

def getSHELL32_ShellExecuteExW():
    # target_addr = shell32_handle_addr + 0x4EDD0
    ctypes.windll.kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    ctypes.windll.kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    ctypes.windll.kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    ctypes.windll.kernel32.GetProcAddress.restype = ctypes.c_void_p
    
    shell32_handle_addr = ctypes.windll.kernel32.GetModuleHandleW(u'SHELL32.dll')
    ShellExecuteExW_addr = ctypes.windll.kernel32.GetProcAddress(shell32_handle_addr, b'ShellExecuteExW')
    return ShellExecuteExW_addr

def WriteProcessMemory(addr, value):
    global hProcess
    
    ctypes.windll.kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    ctypes.windll.kernel32.WriteProcessMemory.restype = wintypes.BOOL
    ctypes.windll.kernel32.WriteProcessMemory(hProcess, addr, value, len(value), None)
    return

def ReadProcessMemory_String(addr):
    global hProcess
    
    ctypes.windll.kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    ctypes.windll.kernel32.ReadProcessMemory.restype = (ctypes.c_ubyte * 100)
    
    data = (ctypes.c_ubyte * 100)()
    bytesRead = ctypes.c_ulonglong()
    
    ctypes.windll.kernel32.ReadProcessMemory(hProcess, addr, ctypes.byref(data), ctypes.sizeof(data), ctypes.byref(bytesRead))
    return data

def ReadProcessMemory_4byte(addr):
    global hProcess
    
    ctypes.windll.kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    ctypes.windll.kernel32.ReadProcessMemory.restype = ctypes.c_ulong
    
    data = ctypes.c_ulong()
    bytesRead = ctypes.c_ulonglong()
    
    ctypes.windll.kernel32.ReadProcessMemory(hProcess, addr, ctypes.byref(data), ctypes.sizeof(data), ctypes.byref(bytesRead))
    return data.value
    
def hook():
    global hProcess, pointer_addr, offset_addr
    
    for process in psutil.process_iter(['name', 'pid']):
        if process.info['name'] == process_name:
            process_id = process.info['pid']
            break
    else:
        return False
    
    if process_id is None:
        print("[Error] Process Id")
        return False
    
    PROCESS_ALL_ACCESS = 0x1F0FFF
    hProcess = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
    if hProcess is None:
        print("[Error] Process Handle")
        return False
    
    hook_addr = VirtualAlloc(512)
    pointer_addr = VirtualAlloc(81920)
    offset_addr = VirtualAlloc(4)

    ShellExecuteExW_addr = getSHELL32_ShellExecuteExW()
    print(f'[] Target_Address(ShellExecuteExW API): {hex(ShellExecuteExW_addr)}')
    print(f'[] Hooking_Address: {hex(hook_addr)}')
    print(f'[] Pointer_Address: {hex(pointer_addr)}')
    print(f'[] Offset_Address: {hex(offset_addr)}')
    
    hook_addr_bytes = struct.pack('<Q', hook_addr)
    jmp_array = b"\xFF\x25\x00\x00\x00\x00" + hook_addr_bytes + b"\xC3"
    WriteProcessMemory(ShellExecuteExW_addr, jmp_array)
    
    offset_addr_bytes = struct.pack('<Q', offset_addr)
    pointer_addr_bytes = struct.pack('<L', pointer_addr - (hook_addr+0xE) - 7)
    return_addr_bytes = struct.pack('<Q', ShellExecuteExW_addr + 0xE)
    hook_arry = b"\x50\x56\x51\x57\x48\xA1" + offset_addr_bytes + b"\x48\x8D\x35" + pointer_addr_bytes + b"\x48\x01\xC6\x48\x05\x00\x01\x00\x00\x48\xA3" + offset_addr_bytes + b"\x48\xB9\x00\x01\x00\x00\x00\x00\x00\x00\x48\x8B\x07\x48\x89\x06\x48\xFF\xC6\x48\xFF\xC7\xE2\xF2\x5F\x59\x5E\x58\xFF\x25\x00\x00\x00\x00" + return_addr_bytes
    # print(hook_arry)
    WriteProcessMemory(hook_addr, hook_arry)
    return True

offset_value = 0
def detection():
    global offset_value
    
    while True:
        if offset_value > ReadProcessMemory_4byte(offset_addr):
            os._exit(1)
            
        if offset_value != ReadProcessMemory_4byte(offset_addr):
            data = ReadProcessMemory_String(pointer_addr + offset_value)
            
            url = ''
            for i in range(len(data)-1):
                if chr(data[i]) == '\x00' and chr(data[i+1]) == '\x00':
                    break
                elif chr(data[i])=='\x00':
                    continue
                url += chr(data[i])
                
            print(f'[] Detection URL: {url}')
            
            if url not in urls:
                urls[url]=send2server(url)
            elif urls[url]==-1:
                urls[url]=send2server(url)                
            
            if urls[url]==0:
                #정상으로 판단
                print(f"{url}-정상")
                res = windll.user32.MessageBoxW(0,"해당 url로 접속하겠습니까?","분류 결과 정상",4)
                if res ==6: #정상
                    print("url 접속하는 코드 실행")
                else:
                    print("url로 접속하지 않는 코드")
            elif urls[url]==1:
                #악성으로 판단
                print(f"{url}-악성")
                res = windll.user32.MessageBoxW(0,"해당 url로 접속하겠습니까?","분류 결과 악성",4)
                if res==6: #정상
                    print("url 접속하는 코드 실행")
                else:
                    print("url로 접속하지 않는 코드")
                
            else:
                print("서버 점검 중입니다.")
                
            # print(''.join([chr(i) for i in url]).rstrip('\x00'))
            
            offset_value = ReadProcessMemory_4byte(offset_addr)
            
        time.sleep(1)
        
#승인 유무를 판단.
def send2server(domain):
    # parser = domain.split("://")
    # http= parser[0]
    # url= parser[1] if parser[1][-1]!="/" else parser[1][:-1]
    data = {
        'target' : domain,
    }
    try:
        res = requests.post(f"http://127.0.0.1:8000",data=data,timeout=5)
    except:
        return -1
    return int(res.text)

def run(target):
    os.system(target,)


if __name__=="__main__":
    
    if getattr(sys, 'frozen', False):
        dir = sys._MEIPASS
    else:
        dir = os.path.join(os.path.dirname(__file__),'sfile')

    process_name = "SumatraPDF-3.4.6-64.exe"
    process = os.path.join(dir,process_name)

    t1 = threading.Thread(target = run, name = 'thread1',args=(process,))
    t1.start()

    time.sleep(1.5)
    if hook():
        print('[] Complete Hook')
        detection()
    else:
        print('[] Failed Hook')

# pyinstaller -F ex.py --add-data="sfile/;." --name=test.exe