import re
import zlib
import cv2

from scapy.all import *

pictures_directory = "/root/Semi/kyberi/kuvat"
faces_directory    = "/root/Semi/kyberi/kuvat"
pcap_file          = "cappi.cap"
packet_count       = 350



def sniff_packets(packet_count):

       pkts = sniff(iface="eth0", count=packet_count)
       wrpcap(pcap_file,pkts)

       return True

def get_http_headers(http_payload):

        print "get http headers called"
	
	try:
		# split the headers off if it is HTTP traffic
		headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]

                # print headers_raw
	
		# break out the headers
		headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
                # print headers
	except:
	    return None
    
     if "Content-type" not in headers:
	    return None
	
	return headers

def extract_image(headers,http_payload):
        print headers	
	image      = None
	image_type = None
	
	try:
		if "image" in headers['Content-type']:
			
			# grab the image type and image body
			image_type = headers['Content-type'].split("/")[1]
		        print image_type
			image = http_payload[http_payload.index("\r\n\r\n")+4:]
		
			# if we detect compression decompress the image
			try:
				if "Content-Encoding" in headers.keys():
					if headers['Content-Encoding'] == "gzip":
						image = zlib.decompress(image,16+zlib.MAX_WBITS)
					elif headers['Content-Encoding'] == "deflate":
						image = zlib.decompress(image)
			except:
				pass
		
	except:
		print "f"
        

      
	
	return image,image_type

def http_assembler(pcap_file):

	carved_images   = 0

	a = rdpcap(pcap_file)

        print "Capfile: %s" % pcap_file	

	sessions      = a.sessions()	

	for session in sessions:

		http_payload = ""
		
		for packet in sessions[session]:
	
			try:
				if packet[TCP].dport == 80 or packet[TCP].sport == 80:
	                                   
					# reassemble the stream into a single buffer
					http_payload += str(packet[TCP].payload)
	
			except:
				pass
	
		headers = get_http_headers(http_payload)
                
  
		if headers is None:
			continue
	
		image,image_type = extract_image(headers, http_payload)
	
		if image is not None and image_type is not None:				
		
			# store the image
                        print "storing image"
			file_name = "%s-sniffi_%d.%s" % (pcap_file,carved_images,image_type)
			fd = open("%s/%s" % (pictures_directory,file_name),"wb")
			fd.write(image)
			fd.close()
			
			carved_images += 1
			
	return carved_images

if sniff_packets(packet_count) is True:
        carved_images = http_assembler(pcap_file)

print "Tallennettu %d kuvaa" % carved_images
