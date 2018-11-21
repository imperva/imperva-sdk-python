import imperva_sdk
import getopt, sys


def main():

  # read commandline arguments, first
  fullCmdArguments = sys.argv
  # - further arguments
  argumentList = fullCmdArguments[1:]

  unixOptions = "ho:s:u:p:a:"
  gnuOptions = ["help", "output", "server", "username", "password", "agents"]

  try:
      arguments, values = getopt.getopt(argumentList, unixOptions, gnuOptions)
  except getopt.error as err:
      # output error, and return with an error code
      print (str(err))
      sys.exit(2)

  agentsOnly = False
  # evaluate given options
  for currentArgument, currentValue in arguments:
      if currentArgument in ("-s", "--server"):
          server = currentValue
      elif currentArgument in ("-u", "--username"):
          username = currentValue
      elif currentArgument in ("-p", "--password"):
          password = currentValue
      elif currentArgument in ("-h", "--help"):
          print ("Please use the following syntax: Export.py -o <output file> -s <source mx IP> -u <username> -p <password>")
      elif currentArgument in ("-o", "--output"):
          outputFile = currentValue
      elif currentArgument in ("-a", "--agents"):
          agentsOnly=True

  try :
      source_mx = imperva_sdk.MxConnection(Host=server, Username=username,Password=password)
      if agentsOnly:
          print(("About to export Agents configuration from (%s)") % (server))
          source_export = source_mx.export_agent_configurations()
      else: #default - export all
          print(("About to export Full configuration from (%s)") % (server))
          source_export = source_mx.export_to_json(Discard=['web_application_custom', 'web_service_custom','http_protocol_signatures','web_profile'])

  except RuntimeError as err:
      print (("Error exporting from (%s)") % (server))
      print (err)
      sys.exit(2)

  try:
      # json.dump() return ASCII-only by default so no encoding is needed
      with open(outputFile, 'w') as f:
          f.write(source_export)
          f.close()
      print(("Export was successfully written to output file (%s)") % (outputFile))
  except Exception as e:
      print (("Error writing export to output file (%s)") % (outputFile))

  source_mx.logout()

if __name__ == "__main__":
  main()