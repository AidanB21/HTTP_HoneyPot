#libraries:
import logging;
from logging.handlers import RotatingFileHandler
import socket
import paramiko        
import socket    
import threading                                                             

#constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

host_key = paramiko.RSAKey(filename = 'server.key')

#loggers & logging files
funnel_logger = logging.getLogger('FunnelLogger') #going to capture username, password, IP
funnel_logger.setLevel(logging.INFO) #sets where the logging will be going to
funnel_handler = RotatingFileHandler('audits.log', maxBytes = 2000, backupCount = 5)         #creates an audit log
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')                                              #going to capture username, password, IP
creds_logger.setLevel(logging.INFO)                                                          #sets where the logging will be going to
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes = 2000, backupCount = 5)      #creates another log 
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


#Emulated Shell
                                                                                              #Fake terminal to trick the hacker into thinking that they have gained access
def emulated_shell(channel, client_ip):
    channel.send(b'corporate-jumpbox2$ ')
    command = b""
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()

        command += char

        if char == b'\r':                                                                     #commands to trick and respond to the hackers
            if command.strip() == b'exit':
                response = b'\n Goodbye!\n'
                channel.close()
            elif command.strip() == b'pwd':
                response = b'\n\\usr\\local' + b'\r\n'
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            elif command.strip() == b'whoami':
                reposnse = b"\n" + b"whoamiP" + b'\r\n'
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')

            elif command.strip() == b'ls':
                response = b'\n' + b"jumpbox1.conf" + b'\r\n'
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')

            elif command.strip() == b'cat jumpbox1.conf':
                response = b'\n' + b"go to deeboodah.com" + b'\r\n'
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')

            else:
                response = b"\n" + bytes(command.strip()) + b"\r\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')

            channel.send(response)
            channel.send(b'corporate-jumpbox2$ ')
            command = b""



#SSH Server + Sockets

class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username = None, input_password = None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        
    def get_allowed_auth(self):
        return "password"
    
    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted a connection with ' + f'username: {username}, ' + f'password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL
        

    def check_channel_shell_request(self, channel): #checks to make sure you have a request
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True
    

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")


    try:
        
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password = password)

        transport.add_server_key(host_key)

        transport.start_server(server = server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to the terminal! \r\n\r\n"
        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)


    except Exception as error:
        print(error)
        print("!!! Error !!!")

    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("!!!Error!!!")
        client.close()



#Provision SSH-based honeypot

def honeypot(address, port, username, password):
    #create tcp socket
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #allow for socket reuse right after it is closed
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #bind the socket to the specified address and port
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH Server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target = client_handle, args = (client, addr, username, password))
            ssh_honeypot_thread.start()                                                                #implementing threading to handle multiple connections

        except Exception as error:
            print(error)

#start the honeypot server on the local host
honeypot('127.0.0.1', 2223, username=None, password=None)