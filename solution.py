from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    # Don’t send the packet yet , just return the final packet in this function.
    #Fill in end

    # So the function ending should look like this
    ID = os.getpid() & 0xFFFF
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        # print("HERE")
        # print(type(htons(myChecksum)))
        myChecksum = htons(myChecksum) & 0xffff
    else:
        # print("HERE")
        # print(type(htons(myChecksum)))
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    packet = header + data
    #print(packet)
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace
    tracelist2 = [] #This is your list to contain all traces
    types = None
    for ttl in range(1,MAX_HOPS):
        tracelist1 = [str(ttl)]
        if types == "0":
            break
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)

            #Fill in start
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            #Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl)) # Here we are converting the ttl variable into a bytes object formatted according to "I"
            #Telling socket to set TTL of packets sent to the format above.
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                t = time.time()
                mySocket.sendto(d, (hostname, 0))
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    tracelist1.append("*")
                    tracelist1.append("Request timed out.")
                    #Fill in start
                    #You should add the list above to your all traces list
                    #tracelist2.append("* * * Request timed out.")
                    #Fill in end
                else:
                    recvPacket, addr = mySocket.recvfrom(1024)
                    timeReceived = time.time()
                    timeLeft = timeLeft - howLongInSelect
                    types = struct.unpack_from("b", recvPacket, offset=20)
                    types = "{}".format(types[0])
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    tracelist1.append("{}ms".format(int((timeReceived - t)*1000)))
                    #print("{}ms".format(int(timeReceived - t)))
                if timeLeft <= 0:
                    tracelist1.append("*")
                    tracelist1.append("Request timed out.")
                    #Fill in start
                    #You should add the list above to your all traces list
                    #tracelist2.append("* * * Request timed out.")
                    #Fill in end
            except timeout:
                tracelist1.append("*")
                tracelist1.append("Request timed out.")
                continue # Basically tells program not to worry about dealing with any errors it got
            if "Request timed out." not in tracelist1:

                #else:
                #Fill in start
                #Fetch the icmp type from the IP packet
                ip = struct.unpack_from("!BBBB", recvPacket, offset=12)
                ip = "{}.{}.{}.{}".format(ip[0],ip[1],ip[2],ip[3])
                tracelist1.append(ip)
                #print(ip)
                #icmpType =
                #Fill in end
                print_type(types, recvPacket, ttl, timeReceived, t, addr)
                try: #try to fetch the hostname
                    #Fill in start
                    dest = gethostbyaddr(ip)
                    #print(dest[0])
                    tracelist1.append(dest[0])
                    #Fill in end
                except herror:   #if the host does not provide a hostname
                    #Fill in start
                    #print("hostname not returnable")
                    tracelist1.append("hostanme not returnable")
            print("\t".join(tracelist1))
                    #Fill in end
            tracelist2.append(tracelist1)

        mySocket.close()
    return tracelist2
def print_type(types, recvPacket, ttl, timeReceived, t, addr):
    if types == "11":
        bytes = struct.calcsize("d")
        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
        # Fill in start
        # You should add your responses to your lists here
        #tracelist2.append(timeSent)

        # Fill in end
    elif types == "3":
        bytes = struct.calcsize("d")
        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
        # Fill in start
        # You should add your responses to your lists here

        #tracelist2.append(timeSent)
        # Fill in end
    elif types == "0":
        bytes = struct.calcsize("d")
        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
        # Fill in start

        # You should add your responses to your lists here and return your list if your destination IP is met
        #tracelist2.append(timeSent)
        #print(" %d   %.0fms %s" % (ttl, (timeReceived - t) * 1000, addr[0]), end=" ")
if __name__ == '__main__':
    get_route("google.co.il")




