import time
from scapy.all import *
from requests import *

conf.iface='Intel(R) Dual Band Wireless-AC 8260'

list=[]
dgalist = open('dga.txt','r')
dgalist = (dgalist.readlines())[18:]
for dga in dgalist :
	list.append(dga.split('\t')[1])
data = set(list)

#Capture and Filter DGA
def capture(packet):
	if packet:
		i =0
		for p in packet:
			src = p[i][IP].src
			dst = p[i][IP].dst
			sport = p[i][UDP].sport
			dport = p[i][UDP].dport
			qr = str(p[i][DNS].qr)
			rcode = str(p[i][DNS].rcode)

			if '0' in qr:
				qr = 'Query'
				qname = p[i][DNS].qd.qname
				if type(qname) == bytes:
					qname = (qname.decode('utf-8'))[:-1]
				if qname in data:
					print("[*] Found DGA Request:-->",src,sport,qr,qname)

			if '1' in qr:
				if '0' in rcode:
					for j in range(10):
						try:
							qr = 'Response'
							rrname = p[j][DNS].an[j].rrname
							rdata = p[j][DNS].an[j].rdata
							if type(rrname) == bytes:
								rrname = (rrname.decode('utf-8'))[:-1]
								if type(rdata) == bytes:
									rdata = (rdata.decode('utf-8'))[:-1]
							if rrname in data:
								print ("[*] Found DGA Response:-->",src,dst,qr,rrname,rdata,"\n")
						except Exception as e:
							pass

		i = i + 1
		
#update dgafile
def dgafileupdate():
	url = 'http://data.netlab.360.com/feeds/dga/dga.txt'
	dgafile = get(url)
	with open('./dga.txt','w') as f:
		f.write(dgafile.text)
		print('Download DGAFile Finished')

if __name__ == '__main__':
	sniff(prn=capture,filter='udp port 53')
	while True:
		dgafileupdate()
		time.sleep(86400)
