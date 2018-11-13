import imperva_sdk
import json
import getopt, sys
import io

# read commandline arguments, first
fullCmdArguments = sys.argv
# - further arguments
argumentList = fullCmdArguments[1:]

print(argumentList)

unixOptions = "hi:l:s:u:p:"
gnuOptions = ["help", "input", "logfile", "server","username","password"]

try:
    arguments, values = getopt.getopt(argumentList, unixOptions, gnuOptions)
except getopt.error as err:
    # output error, and return with an error code
    print (str(err))
    sys.exit(2)

# evaluate given options
for currentArgument, currentValue in arguments:
    if currentArgument in ("-s", "--server"):
        server = currentValue
    elif currentArgument in ("-u", "--username"):
        username = currentValue
    elif currentArgument in ("-p", "--password"):
        password = currentValue
    elif currentArgument in ("-h", "--help"):
        print ("Please use the following syntax: Import.py -i <input file> -l <log file> -s <target mx IP> -u <username> -p <password>")
    elif currentArgument in ("-i", "--input"):
        inputFile = currentValue
    elif currentArgument in ("-l", "--logfile"):
        logFile = currentValue
try :
    target_mx = imperva_sdk.MxConnection(Host=server, Username=username,Password=password)
except:
    print (("Error opening connection to (%s)") % (server))

try:
    with io.open(inputFile, 'r', encoding='utf-8') as f:
        loaded_data = json.load(f)
except:
    print (("Error loading from file (%s)") % (inputFile))

print(loaded_data)
#log = target_mx.import_from_json(Json=loaded_data,update=False)
#print(log)

#with io.open(logFile, 'r', encoding='utf-8') as logf:
#    logf.write(log)

