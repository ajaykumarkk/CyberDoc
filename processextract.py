import psutil
from dbhandler import *
from win32com.client import Dispatch
from test import *
from filehandler import *
from multiprocessing import Process,Manager
import time
import os

def getversioninfo(path):
	ver_parser = Dispatch('Scripting.FileSystemObject')
	info = ver_parser.GetFileVersion(path)
	#print(vars(ver_parser))
	if info == 'No Version Information Available':
		info = None
	return info


if __name__ == '__main__':
	dbCreate()
	wl=[]
	with open('whitelist.txt', 'r+') as f:
		wl = [line.rstrip('\n') for line in open('whitelist.txt')]
	#print(wl)
	proc_dict={p.pid: p for p in psutil.process_iter()}
	print("Total no.of prpocess : "+str(len(proc_dict.keys())))
	for id in proc_dict.keys():
		hash_temp=""
		try:
			#print("Checking for process"+proc_dict[id].name())
			hash_temp=md5Checksum(proc_dict[id].exe())
			if getVT(hash_temp) == -1:
				dbInsertp_q(hash_temp)
			if dbsearch(hash_temp) == True and getVT(hash_temp) > 4:
				print("Killing process"+proc_dict[id].name())#gzip
				proc_dict[id].kill()
			else:
				#print("-->"+proc_dict[id].name()+" : "+getversioninfo(proc_dict[id].exe()))
				getversioninfo(proc_dict[id].exe())
			if proc_dict[id].exe() not in wl and proc_dict[id].name() not in wl:
				print("process not in white list : "+proc_dict[id].name())
		except Exception as e:
				pass
				#print(e)
			#print(proc_dict[id].name())
			
	print("Process parse complete")
	pdat = 	getpdata()		
	if pdat == False:
		print("No unknown applications found on system")
	else:
		l=[h[0] for h in pdat] 
		print("Statrting the hash calculation process total hashes in the queue"+str(len(l)))
		checkvt(l,0)
	proc_list=[]
	paths=[]
	try:
		with open('paths.txt', 'r+') as f:
			paths = [line.rstrip('\n') for line in open('paths.txt')]
		for p in paths:
			p1=Process(target=scan_path, args=(os.path.abspath(p),))
			p1.start()
			proc_list.append(p1)
		print(proc_list)
	except KeyboardInterrupt:
		for i in proc_list:
			i.terminate()
	plist = [p for p in psutil.process_iter()]		
	while True:		
		pdat = 	getfdata()		
		if pdat == False:
			pass
		else:
			l=[h[0] for h in pdat]
			print(l)
			print("Statrting the hash calculation process total hashes in the queue"+str(len(l)))
			checkvt(l,1)
		
		plist1 = [p for p in psutil.process_iter()]
		diff = list(set(plist1)-set(plist))
		if len(diff) > 0:
			print("addedd"+str([p.name() for p in diff]))
			try:
				for p in diff:
					hash_temp=md5Checksum(p.exe())
					if getVT(hash_temp) == -1:
						dbInsertp_q(hash_temp)
					if dbsearch(hash_temp) == True and getVT(hash_temp) > 4:
						print("Killing process"+p.name())
						proc_dict[id].kill() #gzip
					if p.exe() not in wl and p.name() not in wl:
						print("process not in white list : "+p.name())
			except Exception as e:
				print(e)
			print("Process parse complete")
			pdat = 	getpdata()		
			if pdat == False:
				pass
			else:
				l=[h[0] for h in pdat]
				print("Statrting the hash calculation process total hashes in the queue"+str(len(l)))
				checkvt(l,0)
		#check net connections
		proc_dict={p.pid: p for p in psutil.process_iter()}
		pnet = psutil.net_connections()
		for data in pnet:
			if len(data[4]) <= 0:
				continue
			ip = data[4][0]
			pid = data[6]
			dbcheckip(str(ip))
			if dbcheckip(str(ip)) == True:
				print("Malicious remote Connection "+proc_dict[pid].name())
				proc_dict[pid].kill()
				
		
		
		
		plist = plist1
		