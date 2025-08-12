from socket import *
import os
import sys
import struct
import time
import select
import binascii
import requests

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
# hint: see icmpPing lab

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
    csum += (csum >> 16)
    answer = ~csum
    answer &= 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
# In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
# packet to be sent was made, secondly the checksum was appended to the header and
# then finally the complete packet was sent to the destination.

# Make the header in a similar way to the ping exercise.
# Append checksum to the header.

# Don’t send the packet yet , just return the final packet in this function.

    myChecksum = 0
    ID = os.getpid() & 0xFFFF

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())

    myChecksum = checksum(header + data)

    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    
    # So the function ending should look like this
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):

            # Fill in start
            # Make a raw socket named mySocket
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            # Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []:  # Timeout
                    print(output_format.format("*", "*", "Request timed out.", "-", "-"))
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    print(output_format.format("*", "*", "Request timed out.", "-", "-"))
                    continue

            except timeout:
                continue

            else:

                # Fill in start
                # Fetch the icmp type from the IP packet
                icmp_header = recvPacket[20:28]
                types, icmp_code, icmp_checksum, packet_id, seq_num = struct.unpack("bbHHh", icmp_header)
                # Fill in end

                try:
                    resolved_name = gethostbyaddr(addr[0])[0]
                except:
                    resolved_name = addr[0]

                try:
                    geo_info = requests.get(f"http://ip-api.com/json/{addr[0]}?fields=city,regionName,country,org,status").json()
                    if geo_info.get("status") == "success":
                        geo_location = f"{geo_info.get('city')}, {geo_info.get('regionName')}, {geo_info.get('country')}"
                        org_name = geo_info.get("org")
                    else:
                        geo_location = "Geo lookup failed"
                        org_name = "Org undetermined"
                except:
                    geo_location = "Geo lookup failed"
                    org_name = "Org undetermined"

                rtt_ms = f"{(timeReceived - t) * 1000:.0f} ms"
                host_ip = f"{resolved_name} ({addr[0]})"

                if types == 11:
                    bytes_ = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_])[0]
                    print(output_format.format(ttl, rtt_ms, host_ip, geo_location, org_name))
                elif types == 3:
                    bytes_ = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_])[0]
                    print(output_format.format(ttl, rtt_ms, host_ip, geo_location, org_name))
                elif types == 0:
                    bytes_ = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_])[0]
                    print(output_format.format(ttl, rtt_ms, host_ip, geo_location, org_name))
                    return

                else:
                    print("error")

                break

            finally:
                mySocket.close()


output_format = "{:<6} {:<8} {:<80} {:<50} {:<50}"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        host = sys.argv[1]
        print(f"\nTracerouting {host}! Please wait...\n")
        print(output_format.format("Hop", "RTT", "Host (IP)", "Geolocation", "Organization"))
        try:
            get_route(host)
        except Exception as e:
            print(output_format.format("*", "*", f"Unable to trace {host}: {e}", "-", "-"))
        sys.exit(0)