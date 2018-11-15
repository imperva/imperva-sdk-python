import imperva_sdk
import json
import getopt, sys
import io


def dict_discard(d, Discard=[]):
    if not isinstance(d, (dict, list)):
        return d
    if isinstance(d, list):
        return [dict_discard(v,Discard) for v in d]
    return {k: dict_discard(v,Discard) for k, v in d.items()
            if k not in Discard}

def enum(**enums):
  return type('Enum', (), enums)

VERBOSITY_LEVEL = enum(ERRORS_ONLY=0, ALL=1)

def main():

  # read commandline arguments, first
  fullCmdArguments = sys.argv
  # - further arguments
  argumentList = fullCmdArguments[1:]

  print(argumentList)

  unixOptions = "hi:l:s:u:p:v:"
  gnuOptions = ["help", "input", "logfile", "server", "username", "password", "verbose"]

  try:
      arguments, values = getopt.getopt(argumentList, unixOptions, gnuOptions)
  except getopt.error as err:
      # output error, and return with an error code
      print (str(err))
      sys.exit(2)

  # default verbose will output only the errors that occure during import
  verbose = VERBOSITY_LEVEL.ERRORS_ONLY

  # evaluate given options
  for currentArgument, currentValue in arguments:
      if currentArgument in ("-s", "--server"):
          server = currentValue
      elif currentArgument in ("-u", "--username"):
          username = currentValue
      elif currentArgument in ("-p", "--password"):
          password = currentValue
      elif currentArgument in ("-h", "--help"):
          print ("Please use the following syntax: Import.py -i <input file> -l <log file> -s <target mx IP> -u <username> -p <password> -v <verbose>")
      elif currentArgument in ("-i", "--input"):
          inputFile = currentValue
      elif currentArgument in ("-l", "--logfile"):
          logFile = currentValue
      elif currentArgument in ("-v", "--verbose"):
          verbose = VERBOSITY_LEVEL.ALL if currentValue == '1' else VERBOSITY_LEVEL.ERRORS_ONLY
  try :
      target_mx = imperva_sdk.MxConnection(Host=server, Username=username, Password=password)
  except Exception as e:
      print (("Error opening connection to (%s): %s") % (server, e))


  try:
      with io.open(inputFile, 'r', encoding='utf-8') as f:
          loaded_data = json.load(f)
          loaded_data_2 = dict_discard(loaded_data,['ProtectedIps'])
          json_string = json.dumps(loaded_data_2, indent=4, sort_keys=True, separators=(',', ': '))

  except RuntimeError as err:
      print ("Error loading from file {0}: {1}", inputFile, err)

  try:
      log = target_mx.import_from_json(Json=json_string,update=False)
  except RuntimeError as err:
      print("Error in import: {0}", err)

  if verbose == VERBOSITY_LEVEL.ERRORS_ONLY:
    log = [line for line in log if line['Result']=='ERROR'
                  and 'already exists' not in line['Error Message']]

  for log_entry in log:
      print(log_entry)

  with io.open(logFile, 'w', encoding='utf-8') as logf:
      logs = json.dumps(log,indent=4, separators=(',', ': '))
      logf.write(logs)
      if verbose == VERBOSITY_LEVEL.ERRORS_ONLY:
        logf.write('\n\nTotal Errors: %s' % str(len(log)))
      logf.close()

  target_mx.logout()

if __name__ == "__main__":
  main()