import psutil
from filehandler import *

'''
plist = [p for p in psutil.process_iter()]

while True:
	plist1 = [p for p in psutil.process_iter()]
	diff = list(set(plist1)-set(plist))
	if len(diff) > 0:
		print("addedd"+str([p.name() for p in diff]))
	elif len(list(set(plist)-set(plist1))) !=0:
		print("--"+str(list(set(plist)-set(plist1))))
	plist = plist1
'''

def dbInsert_12():
    conn=dbConnect()
    cursor=conn.cursor()
    f = open("./firehol_level1.netset", "r")
    for line in f.readlines():
        line = line.strip("\n")
        cursor.execute('INSERT INTO malacious_ips(ip_values) values("'+ str(line) + '");')
    conn.commit()
    conn.close()
	
dbInsert_12()