from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dbhandler import *
from multiprocessing import Process,Manager
import time
import os 

class MyHandler(FileSystemEventHandler):
	def on_any_event(self, event):
		text=event.src_path
		try:
			time.sleep(2)
			h=md5Checksum(text)
			pos = getVT(h)
			if pos == -1:
				insert_fe(text,h,event.event_type)
			elif pos < 4:
				insert_fe(text,h,event.event_type)
				updatefhash(h,66,pos,0)#gzip
		except:
			pass
				
def scan_path(path):
	event_handler = MyHandler()
	observer = Observer()
	observer.schedule(event_handler, path, recursive=True)
	observer.start()
	try:
		while True:
			time.sleep(1)
	except:
		pass
	observer.join()
	
