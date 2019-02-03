import os
import subprocess
from subprocess import Popen

def execute_command(cmd):
    try:
        p1 = Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = p1.communicate()
        #print(output)
        return output[0]
    except:
        print('Exception in Executing Command')
        return []

def cdr(path):
    fp = os.path.splitext(path)[0]
    filename= os.path.basename(fp)
    path_only = os.path.dirname(path)
    cmdd = 'ConvertDoc /S ' + fp +".PDF " + '/T '+"D:\\temp\\"+ filename +".DOCX " + '/C3  /M3  /V' 
    cmdr = 'ConvertDoc /S ' + fp +".DOCX " + '/T ' + "D:\\temp\\"+ filename +".PDF " + '/F13  /C12  /M2  /V'
    cmdr_doc = 'ConvertDoc /S ' + "D:\\temp\\"+ filename +".PDF " + '/T '+ path_only +'\\filterd\\'+ filename +".DOCX " + '/C3  /M3  /V' 
    cmdd_pdf = 'ConvertDoc /S ' + "D:\\temp\\"+ filename +".DOCX " + '/T ' + path_only +'\\filterd\\'+ filename +".PDF " + '/F13  /C12  /M2  /V'
    
    if path.endswith(".DOCX") or path.endswith(".docx") or path.endswith(".doc") or path.endswith(".DOC"):
        execute_command(cmdr)
        execute_command(cmdr_doc)
        os.remove("D:\\temp\\"+ filename +".PDF")

    elif path.endswith(".PDF") or path.endswith(".pdf"):
        execute_command(cmdd)
        execute_command(cmdd_pdf)
        os.remove("D:\\temp\\"+ filename +".DOCX")
    else:
        return
    os.remove(fp+".pdf")

