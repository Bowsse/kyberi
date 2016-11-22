import re
import zlib
import cv2

from scapy.all import *

pictures_directory = "/root/Semi"
faces_directory    = "/root/Semi"
pcap_file          = "cappi.cap"
packet_count       = 70



def sniff_packets(packet_count):

       pkts = sniff(iface="eth0", count=packet_count)
       wrpcap(pcap_file,pkts)

       return True

def face_detect(path,file_name):

        img     = cv2.imread(path)
        cascade = cv2.CascadeClassifier("/root/Semi/kyberi/body10/haarcascade_fullbody.xml")
        rects   = cascade.detectMultiScale(img, 1.3, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20,20))

        if len(rects) == 0:
                return False
        		
        rects[:, 2:] += rects[:, :2]

	# highlight the faces in the image        
	for x1,y1,x2,y2 in rects:
		cv2.rectangle(img,(x1,y1),(x2,y2),(127,255,0),2)

	cv2.imwrite("%s/%s-%s" % (faces_directory,pcap_file,file_name),img)

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
	
	        #if "Content-Type" not in headers:
	        #return None
	
	return headers

def extract_image(headers,http_payload):
        print "extract_image called"	
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
		return None,None
	
	return image,image_type

def http_assembler(pcap_file):

	carved_images   = 0
	faces_detected  = 0

	a = rdpcap(pcap_file)

        print "Capfile: %s" % pcap_file	

	sessions      = a.sessions()	

	for session in sessions:

		http_payload = ""
		
		for packet in sessions[session]:
	
			try:
				if packet[TCP].dport > 35000 or packet[TCP].sport == 8000:
	                                   
					# reassemble the stream into a single buffer
					http_payload += str(packet[TCP].payload)
	
			except:
				pass
	
		headers = get_http_headers(http_payload)
                
  
		if headers is None:
			continue
	
		image,image_type = extract_image(headers,http_payload)
	
		if image is not None and image_type is not None:				
		
			# store the image
                        print "storing image"
			file_name = "%s-pic_carver_%d.%s" % (pcap_file,carved_images,image_type)
			fd = open("%s/%s" % (pictures_directory,file_name),"wb")
			fd.write(image)
			fd.close()
			
			carved_images += 1
			
                        print "attempting face detection"
			# now attempt face detection
			try:
				result = face_detect("%s/%s" % (pictures_directory,file_name),file_name)
				
				if result is True:
					faces_detected += 1
			except:
				pass
			

	return carved_images, faces_detected

if sniff_packets(packet_count) is True:
        carved_images, faces_detected = http_assembler(pcap_file)

print "Extracted: %d images" % carved_images
print "Detected: %d faces" % faces_detected
