import psutil
 #导入相应的包
import sys
import os
from ctypes import *
import win32api
import win32con
from subprocess import check_output
# 这里是DLL注入申请的内存大小
FAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = 0x001F0FFF
VIRTUAL_MEN = (0x1000 | 0x2000)
dll_path = 'cmd.exe'
#设黑客的webshell打开终端的时候调用了cmd.exe这个进程,注意是进程！
#如果是linux系统请改为sh这个进程名
dll_len = len(dll_path)

kernel32 = windll.kernel32
user32 = windll.user32
pre = psutil.pids()
num_pre = len(pre)
#检测到黑客的Webshell执行命令而创建进程后,发QQ邮件进行报警
import smtplib
from email.mime.text import MIMEText
msg_from='xxxxxxxxx@qq.com'                                 #发送方邮箱
passwd='abcdefghigklmnop'                                   #填入发送方邮箱的授权码
#https://www.cnblogs.com/lovealways/p/6701662.html授权码使用教程
msg_to='xxxxx@foxmail.com'                                  #收件人邮箱
while(1):
        num_new = len(psutil.pids())
        new = psutil.pids()
        if(num_new != num_pre):
                new_pids = [x for x in new if x not in pre]
                for new_pid in new_pids:
                        try:
                                p = psutil.Process(new_pid)
                                print(p.name())
                                print(p.pid)
                                if (p.name() == "nc.exe"):
                                        p.kill()
                                        print("已经杀死nc进程")
                                elif(p.name() == "cmd.exe"):
                                        print("检测到黑客连接上webshell,并执行了系统命令")
                                        p.kill()
                                        print("已经杀死cmd.exe")
                                elif (p.name() == "sh"):
                                        print("检测到黑客连接上webshell,并执行了系统命令")
                                        #由于是linux系统,无法杀死sh这个进程,命令可以正常返回给黑客
                                        #linux系统的话查看该进程的网络连接会话,根据进程名查PID号
                                        for proc in psutil.process_iter():
                                                if proc.name() == PROCNAME:
                                                        hack = proc.pid
                                                        hgk = str(hack)
                                                        kali = "netstat -ano | findstr {jhn}".format(jhn=hgk)
                                                        print(os.system(kali))
                                                        subject = "python邮件测试"  # 主题
                                                        content = "这是我使用python smtplib及email模块发送的邮件"# 正文
                                                        msg = MIMEText(content)
                                                        msg['Subject'] = subject
                                                        msg['From'] = msg_from
                                                        msg['To'] = msg_to
                                                        try:
                                                                s = smtplib.SMTP_SSL("smtp.qq.com",465)# 邮件服务器及端口号
                                                                s.login(msg_from, passwd)
                                                                s.sendmail(msg_from, msg_to, msg.as_string())
                                                                print("有黑客入侵,已发送邮件")
                                                        except s.SMTPException:
                                                                print("发送失败")
                                        for pid in new_pids:
                                                p = psutil.Process(pid)
                                                if p.name() == 'cmd.exe':
                                                        break
                                                elif p.name() == "sh":
                                                        break
                                        #接下来是进程注入发出弹窗告警!!!!!!!!
                                        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

                                        if not h_process:
                                                print("[*] Couldn't acquire a handle to PID: %s" % pid)

                                                sys.exit()
                                        argv_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEN,
                                                                               FAGE_READWRITE)

                                        written = c_int(0)

                                        kernel32.WriteProcessMemory(h_process, argv_address, dll_path, dll_len,
                                                                    byref(written))

                                        h_user32 = kernel32.GetModuleHandleA("kernel32.dll")

                                        h_loadlib = kernel32.GetProcAddress(h_user32, "MessageBoxA")

                                        thread_id = c_ulong(0)

                                        if not kernel32.CreateRemoteThread(
                                                h_process,
                                                None,
                                                0,
                                                h_loadlib,
                                                argv_address,
                                                0,
                                                byref(thread_id)
                                        ):
                                                print("[*] Failed to inject the DLL. Exiting.")
                                                sys.exit()
                                        else:
                                                win32api.MessageBox(0, "入侵检测已发现黑客入侵行为", '黑客提示')
                        except psutil.Error:
                                continue
                num_pre = num_new
