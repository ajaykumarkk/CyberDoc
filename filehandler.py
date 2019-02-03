from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dbhandler import *
from multiprocessing import Process,Manager
import time
import os 
import os.path 
from cdr import *

class MyHandler(FileSystemEventHandler):
	def on_any_event(self, event):
		text=event.src_path
		try:
			time.sleep(2)
			h=md5Checksum(text)
			pos = getVT(h)
			extension = os.path.splitext(text)[1]
			print(extension)
			if pos == -1:
				insert_fe(text,h,event.event_type)
			elif pos < 4:
				print("Not mailicious")
				insert_fe(text,h,event.event_type)
				updatefhash(h,66,pos,0)
			elif pos > 4:
				print("mailicious "+text)
				insert_fe(text,h,event.event_type)
				updatefhash(h,66,pos,0)
				print("Malicius file Zipping..."+text)
				zip_file(text)
			if extension==".exe" and check_exe(text):
				print("unsigned exe Zipping..."+text)
				zip_file(text)
			if extension==".pdf":
				print("pdf added peforming CDR...")
				cdr(text)
				
		except Exception as e:
			pass
				
def scan_path(path):
	event_handler = MyHandler()
	observer = Observer()
	observer.schedule(event_handler, path, recursive=False)
	observer.start()
	try:
		while True:
			time.sleep(1)
	except:
		pass
	observer.join()
	
