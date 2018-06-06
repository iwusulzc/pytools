import zipfile
import optparse
import threading
import socketserver
import time, sys
import signal
from progressbar import *
import socket
import select

threadNrLock = Semaphore(value = 500)
passwdNrLock = Semaphore(value = 50000)

class passwd_per_s:
	def __init__(self):
		self.__start_time = time.time()
		self.__pre_nr = 0
		self.__cps = 0

	def update(self, nr):
		end_time = time.time()
		interval = end_time - self.__start_time

		if interval < 2.0:
			return self.__cps

		self.__cps = int((nr - self.__pre_nr) / interval)
		self.__pre_nr = nr
		self.__start_time = time.time()

class ZipfileCrack(object):
	
	def __init__(self, file, dictionary, server = 0):
		self.__should_exit = 0
		self.__shutdown_request = False
		self.__is_shut_down = threading.Event()
		self.__server = server
		self.__file = file
		self.__zfile = None
		self.__extract_file = ''
		self.__dictionary = dictionary
		self.__passwd_total_cnt = 0
		self.__passwds_disp = []
		self.__process_passwd_nr = 0
		self.__found_passwd = ''
		self.__test_completed = 0
		self.__online_client = 0
		self.__pb = ProgressBar()
		self.__pps = passwd_per_s()

	def signal_handle(self, signo, data):
		self.__pb.logline('recv signo ' + signo)
		self.__should_exit = 1
		self.__pb.stop()

	def shutdown(self):
		self.__shutdown_request = True
		self.__is_shut_down.wait()

	def file_line_count(self, file):
		cnt = 0
		with open(file, 'r') as file:
			for line in file:
				cnt += 1
		return cnt

	def extractFile(self, zfile, passwd, extract_file):
		try:
			zfile.extract(extract_file, pwd = bytes(passwd.encode('utf-8')))
			self.__pb.logline('[+] Found password:' + passwd)
			self.__found_passwd = passwd
		except:
			pass
		finally:
			threadNrLock.release()

	def open_zipfile(self):
		self.__zfile = zipfile.ZipFile(self.__file)

		(self.__extract_file, filesize) = self.minfile_get(self.__zfile)
		if not self.__extract_file:
			return

		try:
			self.__extract_file = unicode(self.__extract_file, 'cp437').decode('gbk')
		except:
			pass

		self.__pb.logline('extract file: ' + self.__extract_file)
		self.__pb.logline('file size: ' + str(filesize) + 'bytes')

	def minfile_get(self, zfile):
		filesize = 0xfffffffff
		extract_file = ''

		for f in zfile.namelist():
			l = zfile.getinfo(f).file_size
			if l and l < filesize:
				filesize = l
				extract_file = f
		return extract_file, filesize

	def sec2time(self, sec):
		strtmp = ''

		if not sec:
			return strtmp

		m = int(sec / 60)
		if m:
			h = int(m / 60)
			if h:
				remain_time_str = str(h) + ':'
				
				m = int(m - h * 60)
				strtmp += '{:02d}'.format(m) + ':'

				s = int(sec % 60)
				strtmp += '{:02d}'.format(s)
			else:
				strtmp += '{:02d}'.format(m) + ':'

				s = int(sec % 60)
				strtmp += '{:02d}'.format(s)
		return strtmp

	def clean_passwd_cache(self):
		for i in range(len(self.__passwds_disp)):
			self.__passwds_disp.pop()
			passwdNrLock.release()

	def sevrver_recv_thread(self, sock, addr):
		while True:
			if self.__should_exit:
				break

			try:
				data = sock.recv(1024).decode('utf-8')

				if not data:
					break

				for cmd in data.split('\n'):
					if not cmd:
						continue

					if ('Found:' in cmd):
						self.__pb.logline('[+] Found password:' + cmd[6:])
						self.__found_passwd = cmd[6:]
			except:
				break
		sock.close()

	def tcp_send(self, sock, data):
		l = 0
		tl = 0

		while True:
			l = sock.send(data[tl:])
			tl += l
			if (tl == len(data)):
				break

	def server_thread(self, sock, addr):
		t = Thread(target = self.sevrver_recv_thread, args = (sock, addr))
		t.start()

		while True:
			if self.__found_passwd:
				self.passwd_found_notify(sock)

			if self.__test_completed:
				self.test_competed_notify(sock)

			if self.__should_exit:
				break

			if self.__passwds_disp:
				passwd = self.__passwds_disp.pop().encode('utf-8')
				passwdNrLock.release()

				try:
					self.tcp_send(sock, passwd)
				except:
					break

				self.__process_passwd_nr += 1
			else:
				time.sleep(0.2)

		sock.close()
		self.__online_client -= 1

	def server_start(self):
		self.__start_time = time.time()

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind(('', 8888))
		s.listen(50)

		while True:
			if self.__should_exit or self.__found_passwd:
				break

			rlist = [s]
			wlist = []
			xlist = []

			try:
				n = select.select(rlist, wlist, xlist, 1)
				if len(n) and len(n[0]):
					sock, addr = s.accept()
					t = Thread(target = self.server_thread, args = (sock, addr))
					t.start()

					self.__online_client += 1
			except:
				break

			self.log()

		s.close()
		self.clean_passwd_cache()

	def passwd_found_notify(self, s):
		found_passwd = '>Found:' + self.__found_passwd + '\n'
		try:
			s.send(found_passwd.encode('utf-8'))
		except:
			pass

	def test_competed_notify(self, s):
		found_passwd = '>Completed' + self.__found_passwd + '\n'
		try:
			s.send(found_passwd.encode('utf-8'))
		except:
			pass

	def client_send_thread(self, s, t):
		while True:
			if self.__found_passwd:
				self.passwd_found_notify(s)
				self.__should_exit = 1
				break

			if self.__should_exit:
				break;

			time.sleep(1)

	def client_start(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.__server, 8888))

		t = Thread(target = self.client_send_thread, args = (s, 0))
		t.start()

		prev_content = ''

		while True:
			if self.__shutdown_request:
				break

			try:
				data = s.recv(2 * 1024).decode('utf-8')
			except:
				break

			if not data:
				break

			if prev_content:
				data = prev_content + data
				prev_content = ''

			ds = data.split('\n')
			if ds[-1]:
				prev_content = ds[-1]
				
			ds.pop()

			for d in ds:
				data = d.strip('\n')

				type = data[0]

				# cmd recv
				if type == '>':
					# 收到服务器通知，密码已找到则退出
					if ('Found:' in data):
						self.__pb.logline('[+] Found password:' + data[6:])
						self.__found_passwd = data[6:]
						break
					elif ('Completed' in data):
						self.__should_exit = 1
						break
				elif type == '*':
					passwd = data[1:]

				if passwd == '12345890':
					print('passwd recv: ' + passwd)

				self.__process_passwd_nr += 1

				threadNrLock.acquire()
				t = Thread(target = self.extractFile, \
					args = (self.__zfile, passwd, self.__extract_file))
				t.start()

			self.log()	
			
		s.close()
		t.join()

	def log(self):
		try:
			cps = self.__pps.update(self.__process_passwd_nr)
			remain_time = int((self.__passwd_total_cnt - self.__process_passwd_nr) / cps)
		except:
			return

		str_cps = str(cps) + '个/s'
		remain_time_str = ''
		
		if remain_time:
			remain_time_str = self.sec2time(remain_time)
			remain_info = u'大约剩余时间: ' + remain_time_str
		else:
			remain_info = u'测试完成'

		self.__pb.log('online: ' + str(self.__online_client) + ' ' +
			remain_info + ' 进度：{:,}'.format(self.__process_passwd_nr) + 
			'/{:,}'.format(self.__passwd_total_cnt) + ' 测试速度：' + str_cps)

	def passwd_gen(self):
		with open(self.__dictionary, 'r') as passwdFile:
			for line in passwdFile:
				if not self.__shutdown_request:
					break

				passwdNrLock.acquire()
				self.__passwds_disp.insert(0, '*' + line)
		
		while self.__passwds_disp:
			time.sleep(1)

		if self.__process_passwd_nr == self.__passwd_total_cnt:
			self.__test_completed = 1

	def start(self):
		signal.signal(signal.SIGINT, self.signal_handle)

		if (not self.__server):
			self.__passwd_total_cnt = self.file_line_count(self.__dictionary)
			self.__pb.start()
			self.__pb.logline('server starting....')

			t = Thread(target = self.server_start)
			t.setDaemon(True)
			t.start()

			self.passwd_gen()
			self.shutdown()

			self.__pb.logline('main thread waiting...')
			t.join()

		else:
			self.open_zipfile()
			self.__pb.start()
			t = Thread(target = self.client_start)
			t.setDaemon(True)
			t.start()
			t.join()

		self.log()
		self.__pb.stop()

class TcpStreamHandler(socketserver.StreamRequestHandler):
	def recv_thread(self):
		while True:
			self.data = self.rfile.readline().strip()
			print(self.data)
			if ('Found:' in str(self.data)):
				self.logline('[+] Found password:' + self.data[6:])
				self.__found_passwd = self.data[6:]

	def send_thread(self):
		while True:
			self.wfile.write('123456'.encode('utf-8'))
			print('in send_thread')
			time.sleep(1)

	def handle(self):
		t = threading.Thread(target = self.recv_thread)
		t.setDaemon(True);
		t.start()

		t = threading.Thread(target = self.send_thread)
		t.setDaemon(True);
		t.start()
		t.join()

class ThreadTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	pass

if __name__ == '__main__':
	'''
	parser = optparse.OptionParser("usage%prog " + \
		"-s <server ip> -f <zipfile> -d <dictionary>")
	parser.add_option('-s', dest = 'server', type = 'string', \
		help = 'specify server ip')
	parser.add_option('-f', dest = 'zname', type = 'string', \
		help = 'specify zip file')
	parser.add_option('-d', dest = 'dicfile', type = 'string', \
		help = 'specify dictionary file')

	(options, args) = parser.parse_args()
	if (options.zname == None):
		print(parser.usage)
		exit(0)

	if (not options.server) and (options.dicfile == None):
			print(parser.usage)
			exit(0)


	zc = ZipfileCrack(options.zname, options.dicfile, options.server)
	zc.start()
	'''
	HOST, PORT = 'localhost', 9999

	server = ThreadTCPServer((HOST, PORT), TcpStreamHandler)

	server_thread = threading.Thread(target = server.serve_forever)
	server_thread.daemon = True
	server_thread.start()
	while True:
		time.sleep(1)