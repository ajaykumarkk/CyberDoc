import psutil
import hashlib
import sqlite3
from sqlite3 import Error
from win32com.client import Dispatch

def md5Checksum(filePath):
    with open(filePath, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

def dbConnect():
	conn = sqlite3.connect('History_Data.db')
	return conn
	print("Connected Successfully")

def dbCreate():
	conn=dbConnect()
	conn.execute(''' CREATE TABLE if not exists Bad_Hash (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING);''')
	conn.execute(''' CREATE TABLE if not exists VT (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING,total INTEGER,pos INTEGER,notinvt INTEGER);''')
	conn.execute(''' CREATE TABLE if not exists phashes_q (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING, UNIQUE(md5));''')

	#conn.execute(''' CREATE TABLE if not exists Drives (id INTEGER PRIMARY KEY AUTOINCREMENT ,DriveName STRING,FileSystem STRING,Serial STRING,Size STRING);''')

	#print("Table Created Successfully")

def dbInsert(d):
	conn=dbConnect()
	c=conn.cursor()
	c.execute('INSERT INTO Bad_Hash(id,md5) values(NULL,"'+d+'");')
	conn.commit()
	conn.close()
	print("Inserted TO DB : "+d)

def dbInsert(d,t,p):
	conn=dbConnect()
	c=conn.cursor()
	c.execute('INSERT INTO VT(id,md5,total,pos) values(NULL,"'+d+'",'+t+','+p+');')
	conn.commit()
	conn.close()
	print("Inserted TO DB : "+d)
	
def dbInsertp_q(d):
	conn=dbConnect()
	c=conn.cursor()
	c.execute('INSERT OR IGNORE INTO phashes_q(id,md5) values(NULL,"'+d+'");')
	conn.commit()
	conn.close()
	print("Inserted TO DB : "+d)
	
def dbsearch(d):
	conn=dbConnect()
	c=conn.cursor()
	cout=c.execute('select * from Bad_Hash where md5 = "'+d+'";')
	rows = cout.fetchall()
	if len(rows) == 0:
		return False
	else:
		return True
		
def getVT(d):
	conn=dbConnect()
	c=conn.cursor()
	cout=c.execute('select pos from VT where md5 = "'+d+'";')
	rows = cout.fetchall()
	if len(rows) == 0:
		return -1
	else:
		return rows[0][0]

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
			#print(e)
			#print(proc_dict[id].name())
			pass
	print("Process parse complete")
