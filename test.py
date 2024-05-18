import paramiko
import SuidWhiteList
import time


class SSH:
    #登录远程主机
    def login(username, passwd, ip, port=22):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port, username, passwd)
        return client
    def cmd(client, command):
        
        full_command = f"source ~/.bashrc; {command}"
        stdin, stdout, stderr = client.exec_command(full_command)
        return stdout.read().decode()
    def invoke_shell(client):
        shell = client.invoke_shell()
        return shell
    def getfilelist(client, path):
        sftp = client.open_sftp()
        return sftp.listdir(path)
    #tar 打包指定文件或目录

    # 检查SUID文件
    def check_suid(client):
        paths = ['/usr/bin', '/usr/sbin', '/bin', '/sbin']
        suid_files = []
        whitelist = SuidWhiteList.SUIDWHITE
        for path in paths:
            stdin, stdout, stderr = client.exec_command('find %s -perm -4000' % path)
            output = stdout.read().decode().split('\n')
            suid_files += [file for file in output if file not in whitelist]
            suid_files = list(filter(None, suid_files))
        return '\n'.join(suid_files)
    def getfilecontent(client, path):
        sftp = client.open_sftp()
        try:
            with sftp.open(path, 'r') as file_handle:
                return file_handle.read().decode()
        except IOError:
            return f"无法读取文件: {path}"
    # 检查定时任务
    def get_system_info(client):
        commands = ["uname -a", "uptime", "free -m", "df -h"]
        results = {}
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            results[cmd] = stdout.read().decode()
        return results
    # 
    def check_open_ports(client):
        command = "netstat -tuln"
        return SSH.cmd(client, command)

    def check_security_logs(client, log_path="/var/log/auth.log"):
        command = f"cat {log_path} | grep 'Failed'"
        return SSH.cmd(client, command)

    def check_recent_files(client, days=1):
        command = f"find / -mtime -{days}"
        return SSH.cmd(client, command)
    
    def check_passwdandshadow(client):
        passwd = SSH.getfilecontent(client, '/etc/passwd')
        #passwd文件 排除含有 nologin,false 的行
        passwd = '\n'.join([line for line in passwd.split('\n') if 'nologin' not in line])
        passwd = '\n'.join([line for line in passwd.split('\n') if 'false' not in line])
        shadow = SSH.getfilecontent(client, '/etc/shadow')
        return f"passwd 文件内容:\n{passwd}\n\nshadow 文件内容:\n{shadow}"
    
    def check_cron(client):
        cron_tasks = []
        cron_paths = [
            '/etc/cron.d/',
            '/etc/cron.daily/',
            '/etc/cron.hourly/',
            '/etc/cron.weekly/',
            '/etc/cron.monthly/',
            '/var/spool/cron/crontabs/',
            '/var/spool/cron/atjobs/',
            '/var/spool/cron/atspool/'
        ]
        for path in cron_paths:
            try:
                files = SSH.getfilelist(client, path)
                if files:
                    for file in files:
                        full_path = f"{path}/{file}"
                        file_content = SSH.getfilecontent(client, full_path)
                        cron_tasks.append(f"文件 {full_path} 的内容:\n{file_content}")
                else:
                    cron_tasks.append(f"目录 {path} 为空")
            except IOError:
                cron_tasks.append(f"无法访问目录 {path}")

        return '\n'.join(cron_tasks)

    # 在 /etc/login.defs 中检查密码最小长度 PASS_MIN_LEN
    def check_login_defs(client):
        login_defs = SSH.getfilecontent(client, '/etc/login.defs')
        pass_min_len = [line for line in login_defs.split('\n') if 'PASS_MIN_LEN' in line]
        # PASS_MIN_DAYS
        pass_min_days = [line for line in login_defs.split('\n') if 'PASS_MIN_DAYS' in line]
        #  PASS_MAX_DAYS
        pass_max_days = [line for line in login_defs.split('\n') if 'PASS_MAX_DAYS' in line]
        # PASS_WARN_AGE
        pass_warn_age = [line for line in login_defs.split('\n') if 'PASS_WARN_AGE' in line]
        return f"PASS_MIN_LEN: {pass_min_len}\nPASS_MIN_DAYS: {pass_min_days}\nPASS_MAX_DAYS: {pass_max_days}\nPASS_WARN_AGE: {pass_warn_age}"
        
    def check_alias(client):
        return SSH.cmd(client, 'alias')

    def execute_command_via_shell(client, command, timeout=2):
        # 创建交互式 shell 通道
        channel = client.invoke_shell()
        # 等待一段时间，以确保通道已准备好
        time.sleep(1)
        # 清空初始欢迎信息
        if channel.recv_ready():
            initial_output = channel.recv(1024).decode("utf-8")
            print("Initial shell output:", initial_output)
        # 发送命令，注意添加换行符
        channel.send(command + '\n')
        # 等待命令执行完成
        time.sleep(timeout)
        # 读取输出
        output = ""
        while channel.recv_ready():
            output += channel.recv(1024).decode("utf-8")
        # 关闭通道
        channel.close()
        return output
    def check_systemctl_status(client):
        SSH.cmd(client, 'systemctl status >/tmp/systemctl_status.txt')
        return SSH.getfilecontent(client, '/tmp/systemctl_status.txt')

if __name__ == "__main__":
    ip = '172.30.110.142'
    username = 'root'
    password = 'root'
    client = SSH.login(username, password, ip)
    #print(SSH.cmd(client, 'cat ~/.bashrc'))
    print(SSH.check_systemctl_status(client))
        
    