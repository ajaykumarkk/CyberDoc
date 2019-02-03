import sqlite3
from sqlite3 import Error
import hashlib
import subprocess
from subprocess import Popen
import shutil
import os
import time

def dbConnect():
	conn = sqlite3.connect('History_Data.db')
	return conn
	print("Connected Successfully")
	
	
def dbCreate():
	conn=dbConnect()
	conn.execute(''' CREATE TABLE if not exists Bad_Hash (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING);''')
	conn.execute(''' CREATE TABLE if not exists VT (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING,total INTEGER,pos INTEGER,notinvt INTEGER);''')
	conn.execute(''' CREATE TABLE if not exists phashes_q (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING, UNIQUE(md5));''')
	conn.execute(''' CREATE TABLE if not exists File_events (id INTEGER PRIMARY KEY AUTOINCREMENT ,path STRING,md5 STRING, eventType STRING,Time INTEGER,total INTEGER,pos INTEGER,notinvt INTEGER,UNIQUE(md5));''')

	
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
	
	
def md5Checksum(filePath):
    with open(filePath, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()	
		
def dbInsert_vt(d,t,p,nv):
	conn=dbConnect()
	c=conn.cursor()
	try:
		c.execute('INSERT INTO VT(id,md5,total,pos,notinvt) values(NULL,"'+d+'",{},{},{});'.format(t,p,nv))
		conn.commit()
	except Exception as e:
		print(e)
	conn.close()
	print("Inserted TO DB : "+d)

def dbsearch_vt(d):
	conn=dbConnect()
	c=conn.cursor()
	cout=c.execute('select * from VT where md5 = "'+d+'";')
	rows = cout.fetchall()
	if len(rows) == 0:
		return False
	else:
		return True

def getpdata():
	conn=dbConnect()
	c=conn.cursor()
	cout=c.execute('select md5 from phashes_q;')
	rows = cout.fetchall()
	if len(rows) == 0:
		return False
	else:
		return rows
		
def pqclean():
	conn=dbConnect()
	c=conn.cursor()
	cout=c.execute('DELETE FROM phashes_q WHERE EXISTS( SELECT 1 FROM VT Where phashes_q.md5 = VT.md5)')
	print(cout.fetchall())
	conn.commit()
	conn.close()
	return
	
		
def insert_fe(pth,md,evt):
	conn=dbConnect()
	c=conn.cursor()
	try:
		c.execute('INSERT OR IGNORE INTO File_events(id,path,md5,eventType,Time) values(NULL,"'+pth+'","{}","{}",strftime("%s","now"));'.format(md,evt))
		conn.commit()
	except Exception as e:
		print(e)
	conn.close()
	print("Inserted TO DB : "+md)
	
def getfdata():
	conn=dbConnect()
	c=conn.cursor()
	cout=c.execute('select md5 from File_events where notinvt is NULL;')
	rows = cout.fetchall()
	if len(rows) == 0:
		return False
	else:
		return rows

def updatefhash(h,tot,p,nv):
	conn=dbConnect()
	c=conn.cursor()
	try:
		c.execute('update File_events set total = {},pos={},notinvt={}  where md5 = "{}"'.format(tot,p,nv,h))
		conn.commit()
	except Exception as e:
		print(e)
	conn.close()
	print("updated TO DB : "+h)

def dbcheckip(ip):
	conn=dbConnect()
	cursor=conn.cursor()
	cursor.execute('select * from malacious_ips where ip_values="' + str(ip) + '";')
	result = cursor.fetchone()
	if result:
		return True
	else:
		return False
		
def execute_command(cmd):
	try:
		p1 = Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output = p1.communicate()
		return output[0]
	except:
		print('Exception in Executing Command')
		return []

def check_exe(path):
	execute_command("sigcheck64.exe -w res.txt -e "+path)
	f = open("res.txt", "r")
	if f.readlines()[1].find("Signed"):
		return True
	else:
		return False

def check_Imphash(h):
	conn=dbConnect()
	cursor=conn.cursor()
	cursor.execute('select malware_name from Imp_hash where imphash="' + str(h) + '";')
	rows = cout.fetchall()
	if len(rows) == 0:
		return -1
	else:
		return rows[0][0]

def zip_file(path):
	import zipfile
	print("Quantine..")
	zipfile.ZipFile('quarantine.zip', mode='a').write(path)
	time.sleep(2)
	print("Removing mailicoius file.."+path)
	os.remove(path)

def zipfilebyhash(h):
	conn=dbConnect()
	cursor=conn.cursor()
	cursor.execute('select path from File_events where md5="' + str(h) + '";')
	rows = cout.fetchall()
	if len(rows) == 0:
		return -1
	else:
		path = rows[0][0]
		zip_file(path)
'''	
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
	

def unprocessedhandling(h):
	conn=dbConnect()
	c=conn.cursor()
	for hash in h:
		c.execute('UPDATE VT set notinvt = {} WHERE md5="{}";'.format(1,hash))
		conn.commit()
	conn.close()
	return
'''	