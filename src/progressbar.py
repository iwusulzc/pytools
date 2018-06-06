import time, sys
from threading import *

class ProgressBar(object):
	def __init__(self):
		self.__should_exit = 0
		self.__logstr = ''
		self.__time = 0
		self.__pbchar = ['/', '-', '\\', '|', '-']
		self.__pbchar_len = len(self.__pbchar) - 1
		self.__pbchar_index = 0

	def progress_bar(self):
		start = int(time.time())

		while True:
			if self.__should_exit:
				break

			self.print()

			self.__time = int(time.time()) - start
			self.__pbchar_index += 1
			time.sleep(0.2)

	def start(self):
		t = Thread(target = self.progress_bar)
		t.start()

	def stop(self):
		self.print()
		self.__should_exit = 1

	def clean_line(self):
		sys.stdout.write('\r' + ' ' * 80 + '\r')
		sys.stdout.flush()

	def log(self, logstr):
		self.__logstr = logstr

	def logline(self, logstr):
		self.clean_line();
		sys.stdout.write(logstr + '\n')

	def print(self):
		self.clean_line();

		sys.stdout.write('time: ' + str(self.__time) + ' ' + \
			self.__logstr +  ' ' + self.__pbchar[self.__pbchar_index % self.__pbchar_len])
		sys.stdout.flush()