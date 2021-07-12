import sys      #read files from the system
import requests #make an HTTP request to VirusTotal
import hashlib  #hash files we get from the system

file = input("Please enter directory of the hash: ") #Accepts the firectory of the hash we want to test
file = file.strip('"') #Cleans the input
url = "https://www.virustotal.com/vtapi/v2/file/report" #VirusTotal URL

input = ""
apikey = input("Please enter your API key: ") #Accepts the user's API key
apikey = apikey.strip('"') #Cleans the input

try:
    parameters = {'apikey': apikey, 'resource': file} #supply API key and hash to Virus Total
    response = (requests.get(url, params=parameters)).json() #Make an HTTP request
except:
    print("Error, perhaps you entered the wrong API key?") #Display error message 

if response['response_code'] == 0 :
    print(response['verbose_msg'])
elif response['response_code'] == 1 :
    print(response['scans'])
    print("Detected: " + str(response['positives']) + "/" + str(response['total']))
    positives = int(response['positives'])
    if positives > 5:
        print(positives + " engines detected the file as malicious.") #If VirusTotal finds more than 5 AV engines detected the file as malicious, output a message that informs the user and tells them how many AV engines detected the file.
    elif positives <= 5 && positives > 0:
        print(positives + " engines detected the file as malicious. The file may be malicious") #If VirusTotal finds that less than 5 AV engines reported the file as malicious, output a message that indicates the file may be malicious and tells the user how many AV engines detected the file.
    elif positives == 0:
        print("No antivirus engines indicated that the file is malicious, the file is clean") #If no AV engines indicate the file is malicious, output a message that tells the user that the file is clean.
    else:
        print("Error, we could not determine how many entivirus engines indicated the file is malicious") #Display error message
else :
    print("Error, perhaps you entered an invalid hash?") #Display error message

exitmsg = input("Press any key to exit.") #this line of code prevents the program from ending before the user can read their results