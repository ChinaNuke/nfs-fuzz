# Custom mutator based on logs
# 
# Before you run the program, public key for ssh should have been copied to 
# the server. For example, `ssh-copy-id -p 9222 admin@192.168.31.127`


from boofuzz.monitors import BaseMonitor
import collections
import paramiko

# If these keywords appears in the log content, we assumes there is a crash.
CRASH_KEYWORDS = ['nfsd: got error', 'segfault']

class LogMonitor(BaseMonitor):
    def __init__(self, host, port, user='admin', pkey_file='/home/peng/.ssh/id_rsa'):
        BaseMonitor.__init__(self)

        self.host = host
        self.port = port

        # Initialize the ssh client
        private = paramiko.RSAKey.from_private_key_file(pkey_file)
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, port, user, pkey=private)

        self.logs = collections.OrderedDict()
        self.crash_synopsis = ''

    def alive(self):
        return True

    def get_crash_synopsis(self):
        return self.crash_synopsis

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        prev_logs_num = len(self.logs)

        # Retrive logs from the target
        stdin, stdout, stderr = self.ssh.exec_command('dmesg | tail')
        for line in stdout:
            timestamp, log_content = line.strip().split(' ', 1)
            self.logs[timestamp] = log_content

        # If there are new logs, we traverse them to find if a crash keyword is 
        # in them.
        new_logs_num = len(self.logs) - prev_logs_num
        if new_logs_num > 0:
            crash_flag = False
            new_logs = list(self.logs.values())[-new_logs_num:]

            for keyword in CRASH_KEYWORDS:
                for log_content in new_logs:
                    if keyword in log_content:
                        crash_flag = True
                        break
                if crash_flag:
                    break
        
            if crash_flag:
                self.crash_synopsis = '\n'.join(new_logs)
                return False

        return True



if __name__ == "__main__":
    monitor = LogMonitor('192.168.31.127', 9222)
    monitor.post_send()
    print(monitor.logs)
    print(monitor.get_crash_synopsis())