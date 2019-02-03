import requests
import time
import csv
import sys
from dbhandler import *


class GetOutOfLoop( Exception ):
    pass

def getdata(hash,apikey):
	params = {'apikey': apikey, 'resource':hash}
	headers = {"Accept-Encoding": "gzip, deflate","User-Agent" : "gzip,  My Python requests library example client or username"}
	response_dict={}
	try:
		r = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
		if r.status_code == 403:
			return "Forbidden. You don't have enough privileges to make the request"
		elif  r.status_code == 204:
			return "Request rate limit exceeded"
		elif r.status_code == 400:
			return "Bad Request"
		elif r.status_code == 200:
			response_dict = r.json()
			return response_dict
	except Exception as e:
		return "API Request Error"
	return response_dict


def checkvt(lines,fileflag):
	apikeys=['08074dd7e431fa9f6bc342947e4707099c4adcfb4b72090286ed24fc9437f95f','924d105b1634c233f2f72d890fd1340b98cefafe6ef6939f2c88e9cf4eecdf47','c476f9625b273f5e4b4f3c3c4e8adbc33899cf2bcdc695b0ba8cb30cdd01b7f1']
	#print("Got the keys and list"+str(lines))
	if len(apikeys) <= 14 :
		waitime = (60 - len(apikeys) * 4)
	else:
		waitime = 3
	el_flag=True
	hashes = iter(lines)
	unprocessed=[]
	notinvt=[]
	#print(lines)
	try:
		while el_flag:
			for api_key in apikeys:
				for i in range(0,4):
					response_dict={}
					hash=""
					try:#getting hashes from iterator
						while True:
							hash = next(hashes)
							if dbsearch_vt(hash) == False:
								#print("Breaking..")
								break
					except:
						print("End of list")
						el_flag=False
						raise GetOutOfLoop
						
					response_dict=getdata(hash,api_key)
					sample_info={}
					if isinstance(response_dict, str):
						#print("request error for hash :"+hash)
						print("-->"+response_dict+" for Hash "+hash)
						if response_dict == "Request rate limit exceeded":
							print("Changing api key..")
							unprocessed.append(hash)
							break
					elif isinstance(response_dict,dict) and response_dict.get("response_code") == 0:
						#print("Not in VT for hash :"+str(hash))
						dbInsert_vt(hash,0,0,1)
						if fileflag == 1:
							print("file event")
							updatefhash(hash,0,0,1)
						notinvt.append(hash)
					elif isinstance(response_dict,dict) and response_dict.get("response_code") == -2:
						print("In queue for scanning")
						unprocessed.append(hash)
					elif isinstance(response_dict,dict) and response_dict.get("response_code") == 1:
						# Hashes
						sample_info["md5"] = response_dict.get("md5")
						# AV matches
						sample_info["positives"] = response_dict.get("positives")
						sample_info["total"] = response_dict.get("total")
						#csv_handle.write(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]))
						print(sample_info["md5"]+","+str(sample_info["positives"])+","+str(sample_info["total"]))
						dbInsert_vt(sample_info["md5"],sample_info["total"],sample_info["positives"],0)
						if fileflag == 1:
							print("file event")
							updatefhash(hash,sample_info["total"],sample_info["positives"],0)
							if sample_info["positives"] > 4:
								if(zipfilebyhash(hash)) == -1:
									print("Unable to zip need further analysis")
						#csv_handle.write('\n')
					else:
						print("Unknown Error for hash "+hash)
						unprocessed.append(hash)
				print("API KEY : "+str(api_key)+" has ran 4 times.. Changing APi Key..")
			print("WaitTime is "+str(waitime)+" Seconds")
			for i in range(1,waitime):
				print(i,end="\r")
				time.sleep(1)
	except:
		pass
	print("unprocessed hashes "+str(unprocessed))
	print("Hashes in Not in VT"+str(notinvt))
	pqclean()
	

