**\### 捕获SSHD 的 操作**

ps -ef|grep sshd

strace -f -p 1492 -o /tmp/.ssh.log -e read=fdtrace,write,connect -s 2048

