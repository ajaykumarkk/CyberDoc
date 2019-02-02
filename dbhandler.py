import sqlite3
from sqlite3 import Error
import hashlib

def dbConnect():
	conn = sqlite3.connect('History_Data.db')
	return conn
	print("Connected Successfully")
	
	
def dbCreate():
	conn=dbConnect()
	conn.execute(''' CREATE TABLE if not exists Bad_Hash (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING);''')
	conn.execute(''' CREATE TABLE if not exists VT (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING,total INTEGER,pos INTEGER,notinvt INTEGER);''')
	conn.execute(''' CREATE TABLE if not exists phashes_q (id INTEGER PRIMARY KEY AUTOINCREMENT ,md5 STRING, UNIQUE(md5));''')
	conn.execute(''' CREATE TABLE if not exists File_events (id INTEGER PRIMARY KEY AUTOINCREMENT ,path STRING, UNIQUE(md5));''')

	
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