#!/usr/bin/python

import subprocess, sys, time, getopt, logging, socket, time, base64, select
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def decode_proto(pkts):
	proto_table = list(list())
	wrpcap("somepcap.cap", pkts)
	pid = subprocess.Popen(['tshark', '-r', 'somepcap.cap', '-Tfields', '-eframe.protocols'], stdout=subprocess.PIPE)
	out, err = pid.communicate()
	#print "DEBUG: %s" % out
	req_table = out.split('\n')
	for i in req_table:
		proto_table.append(i.split(':'))
	return proto_table


def get_sample(port, pktcount):
	cleared_requests = list()
	requests_proto = list(list())
	req = sniff(filter="udp || tcp[13] & 8 != 0 and dst port "+str(port), count=pktcount)
	proto_table = decode_proto(req)
	for pkt in req:
		if pkt.haslayer('Raw'):
			cleared_requests.append(str(pkt[3]))
	#cleared_requests = list(set(cleared_requests))
	for i in range(0, len(cleared_requests)):
		if len(proto_table[i]) > 4:
			requests_proto.append([cleared_requests[i], proto_table[i]])

	return requests_proto

def fuzz_xmit(pld, address, port, proto):
	if proto == 'tcp':
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setblocking(0)
		while True:
			try:
				s.connect((address, int(port)))
				#s.send('CONNECT 127.0.0.1:80 HTTP/1.1\n\n\n')
				s.send(pld)
				ready = select.select([s], [], [], 1)
				if ready[0]:
					print "\033[31mDEBUG" + s.recv(1024) + "\033[0m"
				#s.send(pld)
				s.close()
				break
			except:
				time.sleep(1)
				sys.stdout.write(".")
	if proto == 'udp':
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.sendto(pld, (address, int(port)))

def usage():
	print """USAGE: ./eelfuzz.py [options]:\n
\t-f, --exfile=<file>\tExecutable file, debugging target
\t-a, --address=<address>\tAddress to sniff on for requests
\t-d, --pid=<pid>\tPID of a process to attach to
\t-c, --count=<num>\tSample packet count
\t-g, --arguments=<args>\tArguments for executable
\t-p, --port=<port>\tPort to sniff on for requests 
\t-h, --help\t This help message\n\n"""
	sys.exit(1)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hf:a:c:g:p:d:", ["help", "exfile=", "address=", "count=", "arguments=", "port=", "pid="])
	except getopt.GetoptError as err:
		print >>sys.stderr, str(err)
		sys.exit(2)

	address = "127.0.0.1"
	port = "7777"
	dbg_port = "25746"
	exfile = ""
	arguments = ""
	pktcount = 3
	pid = 0
	pldcnt = 10

	try:
		for o, a in opts:
			if o in ("-h", "--help"):
				usage()
			elif o in ("-f", "--exfile"):
				exfile = a
			elif o in ("-a", "--address"):
				address = a
			elif o in ("-c", "--count"):
				pktcount = int(a)
			elif o in ("-g", "--arguments"):
				arguments = a
			elif o in ("-p", "--port"):
				port = a
			elif o in ("-d", "--pid"):
				pid = a
			else:
				assert False, "unhandled option"
	except Exception:
		usage()
	
	if exfile == "" and pid == 0:
		print >>sys.stderr, "\nSpecify at least the filename for debugging.\n"
		usage()
		sys.exit(2)
	if pid == 0:
		exec_cmd = [ 'fuzzmon/fuzzmon', '-u', 'tcp:'+address+':'+port, '-l', 
				'DEBUG', '-f', exfile, arguments ] 
	else:
		exec_cmd = [ 'fuzzmon/fuzzmon', '-u', 'tcp:'+address+':'+port, '-l',
				'DEBUG', '-f', "-p", str(pid) ]

	dbg_proc = subprocess.Popen(exec_cmd)
	sample_requests = get_sample(port, pktcount)
	for req in sample_requests:
		print "PROTO DEBUG:\n" + str(repr(req[0]))
		for x in range(0,pldcnt):
			radamsa = subprocess.Popen(["./radamsa/bin/radamsa", "--seed", str(x)], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
			radamsa.stdin.write(str(req[0]))
			out, err = radamsa.communicate()
			#print "\033[31mID: %s PAYLOAD:  %s" %( str(x),  base64.b64encode(out)[:2000] + "\033[0m")
			if 'tcp' in req[1]:
				fuzz_xmit(out, address, dbg_port, 'tcp')
			elif 'udp' in req[1]:
				fuzz_xmit(out, address, dbg_port, 'udp')
				
	dbg_proc.terminate()
	dbg_proc.wait()


if __name__ == "__main__":
	main()

