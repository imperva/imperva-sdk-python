import imperva_sdk
import getopt, sys
import io


def main():

  # read commandline arguments, first
  fullCmdArguments = sys.argv
  # - further arguments
  argumentList = fullCmdArguments[1:]

  print(argumentList)

  unixOptions = "ho:s:u:p:"
  gnuOptions = ["help", "output", "server", "username", "password"]

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
      source_export = source_mx.export_to_json(Discard=['web_application_custom', 'web_service_custom','http_protocol_signatures','web_profile'])
  except RuntimeError as err:
      print (("Error exporting from (%s)") % (server))
      print (err)

  try:
      with io.open(outputFile, 'w', encoding='utf-8') as f:
          f.write(source_export)
          f.close()
      print(("Export was successfully written to output file (%s)") % (outputFile))
  except:
      print (("Error writing export to output file (%s)") % (outputFile))

  source_mx.logout()

if __name__ == "__main__":
  main()