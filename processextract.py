import psutil
from dbhandler import *
from win32com.client import Dispatch

def getversioninfo(path):
	ver_parser = Dispatch('Scripting.FileSystemObject')
	info = ver_parser.GetFileVersion(path)
	#print(vars(ver_parser))
	if info == 'No Version Information Available':
		info = None
	return info


if __name__ == '__main__':
	dbCreate()
	proc_dict={p.pid: p for p in psutil.process_iter()}
	print("Total no.of prpocess"+str(len(proc_dict.keys())))
	for id in proc_dict.keys():
		hash_temp=""
		try:
			#print("Checking for process"+proc_dict[id].name())
			hash_temp=md5Checksum(proc_dict[id].exe())
			#if getVT(hash_temp) == -1:
			dbInsertp_q(hash_temp)
			if dbsearch(hash_temp) == True and getVT(hash_temp) > 4:
				print("Killing process"+proc_dict[id].name())
				proc_dict[id].kill()
			else:
				#print("-->"+proc_dict[id].name()+" : "+getversioninfo(proc_dict[id].exe()))
				getversioninfo(proc_dict[id].exe())
				
		except Exception as e:
				pass
				#print(e)
			#print(proc_dict[id].name())
			
	print("Process parse complete")
