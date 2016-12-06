import sys
#sys.path.insert(0, '/Users/andrewmilgrom/Documents/U of M/4th Year/Fall 2013/EECS 388/Projects/3/part 3/dpkt-1.8')
import dpkt

f = open(sys.argv[1], 'r')
pcap = dpkt.pcap.Reader(f)

synDict = {}
ackDict = {}
numErrors = 0

for ts, buf in pcap:
	try:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		tcp = ip.data
		if type(tcp) == dpkt.tcp.TCP:
			if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
				if ip.dst not in ackDict.keys():
					ackDict[ip.dst] = 0
				ackDict[ip.dst] += 1
			elif tcp.flags & dpkt.tcp.TH_SYN:
				if ip.src not in synDict.keys():
					synDict[ip.src] = 0
				synDict[ip.src] += 1
	except: 
		numErrors += 1

# print "num SYN ips:", len(synDict)
# print "num ACK ips:", len(ackDict)
# print "num ERROR ips:", numErrors

def ip_decode(p):
	return ".".join(["%d" % ord(x) for x in str(p)])

for key in synDict.keys():
	if key not in ackDict.keys():
		print ip_decode(key)
	elif (synDict[key]/float(ackDict[key])) > 3.0:
		print ip_decode(key)
