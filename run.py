import LinuxSniffyScout_ui
import paramiko
import time
import base64,yaml

from PySide6.QtCore import Qt, QCoreApplication
from PySide6.QtGui import QColor, QIcon, QPixmap, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QWidget
class LogoWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(400, 400)
        self.logo_label = QLabel(self)
        self.setWindowIcon(QIcon('logo.ico'))
        self.logo_label.setPixmap(QPixmap('Designer.png'))
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setGeometry(0, 0, 400, 400)
        



class MainWindow(QMainWindow):
    def load_config(self):
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            return config['SUIDWHITE'], config['IPandPort'], config['UsernameandPassword']
        
    def __init__(self):
        super().__init__()
        self.ui = LinuxSniffyScout_ui.Ui_MainWindow()
        self.ui.setupUi(self)
        self.loadnote()
        self.configure_buttons()
        self.configure_initial_settings()
    def configure_buttons(self):
        button_actions = {
            self.ui.pushButton_login: self.login,
            self.ui.pushButton_pwdandshadow: self.check_passwdandshadow,
            self.ui.pushButton_SUID: self.check_suid,
            self.ui.pushButton_cron: self.check_cron,
            self.ui.pushButton_env: self.check_env,
            self.ui.pushButton_rookit: self.check_rookit,
            self.ui.pushButton_pstree: self.check_pstree,
            self.ui.pushButton_findhide: self.check_filehide,
            self.ui.pushButton_hosts: self.check_hosts,
            self.ui.pushButton_bashrc: self.check_bashrc,
            self.ui.pushButton_chattr: self.setchattr,
            self.ui.pushButton_lsattr: self.lsattr,
            self.ui.pushButton_systemctl_status: self.check_systemctl_status,
            self.ui.pushButton_kernel: self.check_kernel,
            self.ui.pushButton_dockerlist: self.load_dockerlist,
            self.ui.pushButton_dockerimages: self.check_dockerimages,
            self.ui.pushButton_dockerlogs: self.check_dockerlogs,
            self.ui.pushButton_cmd: self.cmd,
            self.ui.pushButton_dockerexec: self.check_dockerexec,
            self.ui.pushButton_dockercopyfile: self.dockercopyfile,
            self.ui.pushButton_copyfile2docker: self.copyfile2docker,
            self.ui.pushButton_savenote: self.savenote,
            self.ui.pushButton_userdel: self.userdel,
            self.ui.pushButton_delfile: self.delfile,
            self.ui.pushButton_catfile: self.catfile,
            self.ui.pushButton_savefile: self.savefile,
            self.ui.pushButton_logindefs: self.logindefs,
            self.ui.pushButton_crontab: self.crontab,
            self.ui.pushButton_profile: self.profile,
            self.ui.pushButton_rclocal: self.rclocal,
            self.ui.pushButton_etcinitdmysql: self.etcinitdmysql,
            self.ui.pushButton_mycnf: self.mycnf,
            self.ui.pushButton_httpd: self.httpd,
            self.ui.pushButton_quick_open_apache_proxy: self.quick_open_apache_proxy,
            self.ui.pushButton_restartapache2: self.quick_restartapache2,
            self.ui.pushButton_updateaudidt: self.update_audit,
            self.ui.pushButton_restartaudit: self.restartauditservice,
            self.ui.pushButton_dockernetwork: self.dockernetwork,
            self.ui.pushButton_init1: self.check_init1,
            self.ui.pushButton_restartdocker: self.restartdocker,
            self.ui.pushButton_findstr: self.findstr,
        }

        for button, action in button_actions.items():
            button.clicked.connect(action)
        
        self.ui.pushButton_savefile.setEnabled(False)
        self.ui.pushButton_catfile.clicked.connect(self.enable_savefile)
        
    def configure_initial_settings(self):
        suidwhite, ipandport, usernameandpassword = self.load_config()
        self.ui.lineEdit_ipandport.setText(ipandport)
        self.ui.lineEdit_usernameandpasswd.setText(usernameandpassword)
        self.setWindowIcon(QIcon('logo.ico'))

    def enable_savefile(self):
        self.ui.pushButton_savefile.setEnabled(True)
        

    def logindefs(self):
        self.ui.lineEdit_findstr.setText('/etc/login.defs')
        self.catfile()
        self.ui.pushButton_savefile.setEnabled(True)
    def crontab(self):
        self.ui.lineEdit_findstr.setText('/etc/crontab')
        self.catfile()
        self.ui.pushButton_savefile.setEnabled(True)
    def profile(self):
        self.ui.lineEdit_findstr.setText('/etc/profile')
        self.catfile()
        self.ui.pushButton_savefile.setEnabled(True)
    def rclocal(self):
        self.ui.lineEdit_findstr.setText('/etc/rc.local')
        self.catfile()
        self.ui.pushButton_savefile.setEnabled(True)
    def etcinitdmysql(self):
        self.ui.lineEdit_findstr.setText('/etc/init.d/mysql')
        self.catfile()
        self.ui.pushButton_savefile.setEnabled(True)
    def mycnf(self):
        self.ui.lineEdit_findstr.setText('cat /etc/my.cnf')
        self.catfile()
        self.ui.pushButton_savefile.setEnabled(True)
    def httpd(self):
        self.ui.lineEdit_findstr.setText('cat /usr/local/apache2/conf/httpd.conf')
    def quick_open_apache_proxy(self):
        # sudo a2enmod proxy , sudo a2enmod proxy_http , sudo a2enmod headers , sudo a2enmod rewrite
        result = SSH.cmd(self.client, 'sudo a2enmod proxy && sudo a2enmod proxy_http && sudo a2enmod headers && sudo a2enmod rewrite')
        
        self.print2textEdit(f"以下是执行命令：sudo a2enmod proxy && sudo a2enmod proxy_http && sudo a2enmod headers && sudo a2enmod rewrite:\n{result}")
    def quick_restartapache2(self):
        result = SSH.cmd(self.client, 'sudo systemctl restart apache2 && echo \'重启成功\' || echo \'重启失败\'')
        self.print2textEdit(f"以下是执行命令：sudo systemctl restart apache2:\n{result}")

    def update_audit(self):
        #上传Auditd目录下的 audit.rule , auditd.deb,libauparse.deb文件
        try:
            SSH.cmd(self.client, 'mkdir -p /root/audit')
            SSH.update_file(self.client, 'auditd/audit.rules', '/root/audit/audit.rules')
            SSH.update_file(self.client, 'auditd/auditd.deb', '/root/audit/auditd.deb')
            SSH.update_file(self.client, 'auditd/libauparse.deb', '/root/audit/libauparse.deb')
            self.print2textEdit("上传成功")
            SSH.cmd(self.client, 'chmod 777 /root/audit/audit.rules')
            SSH.cmd(self.client, 'chmod 777 /root/audit/auditd.deb')
            SSH.cmd(self.client, 'chmod 777 /root/audit/libauparse.deb')
            self.print2textEdit("修改权限成功")

            # 逐次安装 libauparse.deb, auditd.deb
            step1 = SSH.cmd(self.client, 'dpkg -i /root/audit/libauparse.deb')
            step2 = SSH.cmd(self.client, 'dpkg -i /root/audit/auditd.deb')
            self.print2textEdit(f"以下是执行命令：安装libauparse.deb:\n{step1}")
            self.print2textEdit(f"以下是执行命令：安装auditd.deb:\n{step2}")
            # cp audit.rules 到 /etc/audit/audit.rules
            SSH.cmd(self.client, 'cp /root/audit/audit.rules /etc/audit/rules.d/audit.rules')

            self.print2textEdit("安装成功，请手动执行auditd -s 启动auditd服务")
        except Exception as e:
            self.print2textEdit(f"上传失败: {e}")
    def dockernetwork(self):
        # 打印 docker容器占用的ip地址
        id = self.ui.comboBox_dockerlist.currentText().split(',')[1]
        result = SSH.cmd(self.client, f'docker inspect {id}|grep IPAddress')
        self.print2textEdit(f"以下是执行命令：docker inspect {id}|grep IPAddress:\n{result}")
        #安装auditd
    def restartauditservice(self):
        result = SSH.cmd(self.client, 'systemctl restart auditd && echo \'重启成功\' || echo \'重启失败\'')
        self.print2textEdit(f"以下是执行命令：systemctl restart auditd:\n{result}")
    def resizeEvent(self, event):
        width = self.width() - 20
        self.ui.textEdit.setFixedWidth(width)
        height = self.height()- 230
        self.ui.textEdit.setFixedHeight(height)
        super().resizeEvent(event)

    def login(self):
        ip, port = self.ui.lineEdit_ipandport.text().split(':')
        username, passwd = self.ui.lineEdit_usernameandpasswd.text().split(':')
        try:
            self.client = SSH.login(username, passwd, ip, port)
            self.print2textEdit("登录成功")
        except Exception as e:
            self.print2textEdit(f"登录失败: {e}")
    def findstr(self):
        findstr = self.ui.lineEdit_findstr.text()
        text = self.ui.textEdit.toPlainText()
        cursor = self.ui.textEdit.textCursor()
        format = QTextCharFormat()
        format.setBackground(QColor("yellow"))
        cursor.movePosition(QTextCursor.Start)
        cursor.select(QTextCursor.Document)
        cursor.setCharFormat(QTextCharFormat())  # Reset format
        cursor.clearSelection()
        index = text.find(findstr, 0)
        while index != -1:
            cursor.setPosition(index)
            cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, len(findstr))
            cursor.mergeCharFormat(format)
            index = text.find(findstr, index + len(findstr))
        cursor.movePosition(QTextCursor.Start)
        self.ui.textEdit.setTextCursor(cursor)
    def print2textEdit(self, text):
        #清空textEdit
        self.ui.textEdit.clear()
        self.ui.textEdit.append(text)
    def print2markdown(self, text):
        #清空textEdit
        self.ui.textEdit.clear()
        self.ui.textEdit.append(f'```{text}```')
    def cmd(self):
        cmd = self.ui.lineEdit_findstr.text()
        try:
            cmd = f"{cmd} >/tmp/cmd.txt 2>&1 && cat /tmp/cmd.txt"
            result = SSH.cmd(self.client, cmd)
            self.print2textEdit(result)
        except Exception as e:
            self.print2textEdit(f"命令执行失败: {e}")

    def check_init1(self):
        # ps -e -o user,pid,ppid,cmd | awk '$3 == 1' | egrep -v "containerd-shim|/lib/systemd/systemd|/usr/sbin/cron|dbus|rsyslogd|containerd|/usr/sbin/sshd|/usr/bin/dockerd|/usr/sbin/arpd|/bin/login|/usr/sbin/vnstatd"
        try:
            result = SSH.cmd(self.client, 'ps -e -o user,pid,ppid,cmd | awk \'$3 == 1\' | egrep -v "containerd-shim|/lib/systemd/systemd|/usr/sbin/cron|dbus|rsyslogd|containerd|/usr/sbin/sshd|/usr/bin/dockerd|/usr/sbin/arpd|/bin/login|/usr/sbin/vnstatd"')
            self.print2textEdit(result)
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_passwdandshadow(self):
        try:
            result = SSH.check_passwd_and_shadow(self.client)
            self.print2textEdit(result)
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_suid(self):
        try:
            result = SSH.check_suid(self.client)
            self.print2textEdit(result)
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_cron(self):
        try:
            result = SSH.check_cron(self.client)
            self.print2textEdit(result)
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_env(self):
        try:
            result = SSH.check_env()
            self.print2textEdit(result)
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_rookit(self):
        try:
            result = SSH.check_rootkit(self.client)
            self.print2textEdit(f"以下是执行命令：可疑的rookit:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_pstree(self):
        try:
            result = SSH.check_pstreel(self.client)
            self.print2textEdit(f"以下是执行命令：当前进程:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_filehide(self):
        try:
            result = SSH.find_hide(self.client)
            self.print2textEdit(f"以下是执行命令：/etc /run /root /bin /usr/bin目录下的隐藏文件:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_hosts(self):
        try:
            result = SSH.check_hosts(self.client)
            self.print2textEdit(f"以下是执行命令：/etc/hosts文件内容:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_bashrc(self):
        try:
            result = SSH.check_bashrc(self.client)
            self.print2textEdit(f"以下是执行命令：'cat ~/.bashrc', 'cat ~/.profile', 'cat /etc/profile'文件内容:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def lsattr(self):
        try:
            result = SSH.find_chattr(self.client)
            self.print2textEdit(f"以下是执行命令：特殊属性文件:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")

    def check_systemctl_status(self):
        try:
            result = SSH.check_systemctl_status(self.client)
            self.print2textEdit(f"以下是执行命令：所有服务:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_kernel(self):
        try:
            result = SSH.check_kernel(self.client)
            self.print2textEdit(f"以下是执行命令：内核日志:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")

    def setchattr(self):
        path = self.ui.lineEdit_findstr.text()
        if not path:
            self.print2textEdit("请输入文件路径")
            return
        try:
            result = SSH.set_chattr(self.client, path)
            self.print2textEdit(f"以下是执行命令：{path}文件的特殊属性:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_dockerps(self):
        try:
            result = SSH.check_dockerps(self.client)
            self.print2textEdit(f"以下是执行命令：docker ps:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_dockerimages(self):
        try:
            result = SSH.check_dockerimages(self.client)
            self.print2textEdit(f"以下是执行命令：docker images:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_dockerlogs(self):
        id = self.ui.comboBox_dockerlist.currentText().split(',')[1]
        if not id:
            self.print2textEdit("请先执行刷新docker列表获取id,并选择id")
            return
        try:
            result = SSH.check_dockerlogs(self.client, id)
            self.print2textEdit(f"以下是执行命令：docker logs {id}:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def load_dockerlist(self):
        try:
            result = SSH.check_dockerlist(self.client)
            self.ui.comboBox_dockerlist.addItems(result)
            #打印 docker ps 至textEdit
            cmdstr = 'docker ps'
            dockerps = SSH.cmd(self.client, cmdstr)
            self.print2textEdit(f"以下是执行命令：docker ps:\n{dockerps}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def check_dockerexec(self):
        id = self.ui.comboBox_dockerlist.currentText().split(',')[1]
        if not id:
            self.print2textEdit("请先执行刷新docker列表获取id,并选择id")
            return
        cmd = self.ui.lineEdit_findstr.text()
        try:
            result = SSH.cmd(self.client, f'docker exec {id} {cmd} && echo \'执行成功\' || echo \'执行失败\'')
            self.print2textEdit(f"以下是执行命令：docker exec {id} {cmd}:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def dockercopyfile(self):
        id = self.ui.comboBox_dockerlist.currentText().split(',')[1]
        if not id:
            self.print2textEdit("请先执行刷新docker列表获取id,并选择id")
            return
        #src 用户复制的文件目录
        src = self.ui.lineEdit_findstr.text()
        if '/' in src:
            dst = src.split('/')[-1]
        else:
            dst = src

        try:
            result = SSH.cmd(self.client, f'docker cp {id}:{src} /tmp/{dst} && echo \'复制成功\' || echo \'复制失败\'')
            self.print2textEdit(f"以下是执行命令：docker cp {id}:{src} /tmp/{dst}:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def copyfile2docker(self):
        id = self.ui.comboBox_dockerlist.currentText().split(',')[1]
        if not id:
            self.print2textEdit("请先执行刷新docker列表获取id,并选择id")
            return
        #src 用户复制的文件目录
        src = self.ui.lineEdit_findstr.text()
        if '/' in src:
            dst = src.split('/')[-1]
        else:
            dst = src
        try:
            result = SSH.cmd(self.client, f'docker cp /tmp/{dst} {id}:{src} && echo \'复制成功\' || echo \'复制失败\'')
            self.print2textEdit(f"以下是执行命令：docker cp /tmp/{dst} {id}:{src}:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def restartdocker(self):
        id = self.ui.comboBox_dockerlist.currentText().split(',')[1]
        if not id:
            self.print2textEdit("请先执行刷新docker列表获取id,并选择id")
            return
        try:
            result = SSH.cmd(self.client, f'docker restart {id} && echo \'重启成功\' || echo \'重启失败\'')
            self.print2textEdit(f"以下是执行命令：docker restart {id}:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")

    def savenote(self):
        # 读取 textEdit_1~9 的内容到notebook文件夹下 notebook1~9.txt
        for i in range(1, 10):
            text = eval(f'self.ui.textEdit_{i}.toMarkdown()')
            with open(f'notebook/notebook{i}.md', 'w',encoding='utf-8') as f:
                f.write(text)
    def loadnote(self):
        # 读取notebook文件夹下 notebook1~9.txt 的内容到 textEdit_1~9
        for i in range(1, 10):
            with open(f'notebook/notebook{i}.md', 'r',encoding='utf-8') as f:
                text = f.read()
                eval(f'self.ui.textEdit_{i}.setMarkdown(text)')
    def userdel(self):
        username = self.ui.lineEdit_findstr.text()
        if not username:
            result = SSH.cmd(self.client, 'cat /etc/passwd | grep -v nologin | grep -v false')
            self.print2textEdit(f"没有输入用户名，以下是有疑问的用户列表，执行命令为\ncat /etc/passwd | grep -v nologin | grep -v false:\n{result}")
            return
        try:
            result = SSH.cmd(self.client, f'userdel -rf {username} && echo \'删除成功\' || echo \'删除失败\'')
            self.print2textEdit(f"以下是执行命令：userdel -rf {username}:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")        
    def delfile(self):
        path = self.ui.lineEdit_findstr.text()
        if not path:
            self.print2textEdit("请输入文件路径")
            return
        if '*' in path:
            #不运行rm -rf /*命令，请手动执行相关命令
            self.print2textEdit(f"不允许运行rm -rf */*命令,请手动执行相关命令 \n rm -rf {path}")
        try:
            result = SSH.cmd(self.client, f'rm -rf {path} && echo \'删除成功\' || echo \'删除失败\'')
            self.print2textEdit(f"以下是执行命令：rm -rf {path}:\n{result}")
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def catfile(self):
        path = self.ui.lineEdit_findstr.text()
        if not path:
            self.print2textEdit("请输入文件路径")
            return
        try:
            result = SSH.cmd(self.client, f'cat {path}')
            self.print2textEdit(f"{result}")
            self.ui.pushButton_savefile.setEnabled(True)
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")
    def savefile(self):
        path = self.ui.lineEdit_findstr.text()
        if not path:
            self.print2textEdit("请输入文件路径")
            return
        try:
            data = self.ui.textEdit.toPlainText()
            #先base64编码 然后解码写入文件
            data = base64.b64encode(data.encode()).decode()
            result = SSH.cmd(self.client, f'echo "{data}" | base64 -d > {path} && echo \'写入成功\' || echo \'写入失败\'')
            self.print2textEdit(f"以下是执行命令：echo '{data}' > {path}:\n{result}")
            self.ui.pushButton_savefile.setEnabled(False)
        except Exception as e:
            self.print2textEdit(f"检查失败: {e}")


class SSH:
    # 初始化连接
    @staticmethod
    def login(username, passwd, ip, port=22):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port, username, passwd)
        return client

    @staticmethod
    def cmd(client, command):
        try:
            stdin, stdout, stderr = client.exec_command(command)
            return stdout.read().decode()
        except Exception as e:
            return f"命令执行失败: {str(e)}"

    @staticmethod
    def getfilelist(client, path):
        try:
            sftp = client.open_sftp()
            return sftp.listdir(path)
        except IOError as e:
            return f"无法读取目录: {path}, 错误: {str(e)}"

    @staticmethod
    def getfilecontent(client, path):
        try:
            sftp = client.open_sftp()
            with sftp.open(path, 'r') as file_handle:
                return file_handle.read().decode()
        except IOError:
            return f"无法读取文件: {path}"

    @staticmethod
    def check_suid(client):
        # find / ! -path "/proc/*" -perm -004000 -type f | egrep -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps
        cmdstr = 'find / ! -path "/proc/*" -perm -004000 -type f | egrep -v \'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps\''
        return SSH.cmd(client, cmdstr)

    @staticmethod
    def check_security_logs(client, log_path="/var/log/auth.log"):
        return SSH.cmd(client, f"cat {log_path} | grep 'Failed'")

    @staticmethod
    def check_recent_files(client, days=1):
        return SSH.cmd(client, f"find / -mtime -{days}")

    @staticmethod
    def check_passwd_and_shadow(client):
        passwd = SSH.getfilecontent(client, '/etc/passwd')
        passwd = '\n'.join([line for line in passwd.split('\n') if 'nologin' not in line and 'false' not in line])
        shadow = SSH.getfilecontent(client, '/etc/shadow')
        return f"passwd 文件内容:\n{passwd}\n\nshadow 文件内容:\n{shadow} \n\n修改文件命令: \n vi /etc/passwd \n vi /etc/shadow"

    @staticmethod
    def check_cron(client):
        cron_tasks = []
        cron_paths = [
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
            '/var/spool/cron/crontabs',
            '/var/spool/cron/atjobs',
            '/var/spool/cron/atspool'
        ]
        for path in cron_paths:
            files = SSH.getfilelist(client, path)
            if isinstance(files, list):
                for file in files:
                    full_path = f"{path}/{file}"
                    file_content = SSH.getfilecontent(client, full_path)
                    cron_tasks.append(f"文件 {full_path} 的内容:\n{file_content} \n\n修改文件命令: \n vi {full_path}")
            else:
                cron_tasks.append(files)
        return '\n'.join(cron_tasks)

    #检测环境变量 set | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH|PATH|PROMPT_COMMAND|PS1|IFS'
    def check_env():
        return '''
        环境问题请在终端复制以下命令查找\n\
        set | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH|PATH|PROMPT_COMMAND|PS1|IFS' \n
        LD_PRELOAD 这是一个环境变量，用于指定在所有其他库之前加载的共享库。黑客可以利用它来注入恶意的库，从而劫持正常的系统调用。\n
        LD_LIBRARY_PATH 此环境变量用于指定运行时链接器搜索共享库的路径。如果被设置或修改，可能是为了使执行的程序加载恶意的共享库。\n
        PATH 黑客可能会修改 PATH 环境变量，以指向一个包含恶意版本的常用命令的目录。检查 PATH 是否包含不寻常的或不可信的目录。\n
        PROMPT_COMMAND 这个变量包含一条命令，该命令在每次命令提示符出现之前执行。如果设置了此变量，它可能被用来执行恶意脚本或命令。\n
        PS1 这是 shell 提示符变量。虽然通常用于自定义提示符，但如果被设置为包含执行命令的复杂值，可能是有问题的。。\n
        IFS 这是一个环境变量，用于指定字段分隔符。黑客可以利用它来执行恶意命令。\n
            '''

    # find *.ko
    @staticmethod
    def check_rootkit(client):
        cmdstr = 'find / -path /lib -prune -o -type f -name "*.ko" -print 2>/dev/null'
        return SSH.cmd(client, cmdstr)
    @staticmethod
    def check_pstreel(client):
        return SSH.cmd(client, 'ps -aux')
    @staticmethod
    def find_hide(client):
        return SSH.cmd(client, 'find /etc /run /root /bin /usr/bin /usr/sbin   -type f -name ".*" 2>/dev/null')
    @staticmethod
    def check_hosts(client):
        return SSH.getfilecontent(client, '/etc/hosts')
    @staticmethod
    def check_bashrc(client):
        result = []
        cmdlist = ['cat ~/.bashrc', 'cat ~/.profile', 'cat /etc/profile']
        for cmd in cmdlist:
            result.append(SSH.cmd(client, cmd))
        return '\n'.join(result)
    @staticmethod
    def find_chattr(client):
        return SSH.cmd(client, 'sudo lsattr -R /root /var/www /tmp /bin /usr 2>/dev/null | grep \'\-ia\-\'')
    
    @staticmethod
    def check_systemctl_status(client):
        SSH.cmd(client, 'systemctl status >/tmp/systemctl_status.txt')
        return SSH.getfilecontent(client, '/tmp/systemctl_status.txt')
    @staticmethod
    def check_kernel(client):
        SSH.cmd(client, 'journalctl -k>/tmp/kernel.txt')
        return SSH.getfilecontent(client, '/tmp/kernel.txt')
    


    @staticmethod
    def check_dockerlist(client):
        cmdstr = 'docker ps --format \'{{.ID}}\''
        result_id = SSH.cmd(client, cmdstr)
        cmdstr2 = 'docker ps --format \'{{.Names}}\''
        result_image = SSH.cmd(client, cmdstr2)
        result = []
        result_id = result_id.strip()
        result_image = result_image.strip()
        for id, image in zip(result_id.split('\n'), result_image.split('\n')):
            result.append(f'{image},{id}')
        result = '\n'.join(result).split('\n')
        result = list(filter(None, result))
        return result
    @staticmethod
    #SFTP 上传文件
    def update_file(client, localpath, remotepath):
        sftp = client.open_sftp()
        sftp.put(localpath, remotepath)
        sftp.close()
        
    @staticmethod
    def check_dockerimages(client):
        return SSH.cmd(client, 'docker images')
    @staticmethod
    def check_dockerlogs(client,id):
        return SSH.cmd(client, f'docker logs {id} >/tmp/dockerlogs.txt && cat /tmp/dockerlogs.txt')
    
    def set_chattr(client, path):
        cmdstr1 = f'chattr -ia {path} && lsattr {path}'
        
        return SSH.cmd(client, cmdstr1)
    
    
if __name__ == "__main__":
    app = QApplication([])
    # #展示logo2秒
    logo = LogoWindow()
    logo.show()
    QCoreApplication.processEvents()
    time.sleep(0.5)
    logo.close()
    window = MainWindow()
    window.show()
    app.exec()

