import imperva_sdk
import getopt, sys
import io

# read commandline arguments, first
fullCmdArguments = sys.argv
# - further arguments
argumentList = fullCmdArguments[1:]

print(argumentList)

unixOptions = "ho:s:u:p:"
gnuOptions = ["help", "output", "server","username","password"]

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
        print ("Please use the following syntax: Export.py [-o <output file>] -s <source mx IP> -u <username> -p <password>")
    elif currentArgument in ("-o", "--output"):
        outputFile = currentValue
try :
    source_mx = imperva_sdk.MxConnection(Host=server, Username=username,Password=password)
    source_export = source_mx.export_to_json()
except:
    print (("Error exporting from (%s)") % (server))

try:
    with io.open(outputFile, 'w', encoding='utf-8') as f:
        f.write(source_export)
        f.close()
except:
    print (("Error writing export to output file (%s)") % (outputFile))

print(("Export was successfully written to output file (%s)") % (outputFile))

sys.exit(0)