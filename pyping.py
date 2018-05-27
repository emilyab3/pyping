import os
import sys
import socket
import struct
import select
import time

default_timer = time.clock  # TODO
ICMP_REQUEST_TYPE = 8
ICMP_REPLY_TYPE = 0
ICMP_CODE = 0


def checksum(source):
    checksum_return = 0
    length = len(source)

    for char in range(0, length, 2):
        if char + 1 == length:
            checksum_return += ord(source[char])
            break
        checksum_return += (ord(source[char + 1]) << 8) + ord(source[char])

    checksum_return = (checksum_return >> 16) + (checksum_return & 0xffff)
    checksum_return += (checksum_return >> 16)
    checksum_return = ~checksum_return

    return checksum_return & 0xffff


def receive_one_ping(my_socket, ID, timeout):
    """
    receive the ping from the socket.
    """
    timeLeft = timeout
    while True:
        startedSelect = default_timer()
        whatReady = select.select([my_socket], [], [], timeLeft)
        howLongInSelect = (default_timer() - startedSelect)
        if whatReady[0] == []: # Timeout
            return

        timeReceived = default_timer()
        recPacket, addr = my_socket.recvfrom(1024)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )
        # Filters out the echo request itself.
        # This can be tested by pinging 127.0.0.1
        # You'll see your own request
        if type != 8 and packetID == ID:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return


def send_one_ping(sock, destination, process_id, sequence_num):
    """
    Send one ping to the address given by destination.
    """
    destination = socket.gethostbyname(destination)

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    icmp_checksum = 0

    # Make a dummy header with a 0 checksum.
    header = struct.pack("BBHHH", ICMP_REQUEST_TYPE, ICMP_CODE, icmp_checksum, process_id,
                         sequence_num)

    # pad_bytes = []
    # start_val = 0x42
    # for i in range(start_val, start_val + (self.packet_size)):
    #     pad_bytes += [(i & 0xff)]  # Keep chars in the 0-255 range
    # # data = bytes(pad_bytes)
    # data = bytearray(pad_bytes)

    # Calculate the checksum on the data and the dummy header.
    icmp_checksum = icmp_checksum(header)

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "bbHHh", ICMP_REQUEST_TYPE, 0, socket.htons(icmp_checksum), process_id, 1
    )
    packet = header + data
    sock.sendto(packet, (destination, 1)) # Don't know about the 1


def do_one(dest_addr, timeout):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error:
        print("oops")
        sys.exit()

    process_id = os.getpid() & 0xFFFF

    send_one_ping(sock, dest_addr, process_id)
    delay = receive_one_ping(sock, process_id, timeout)

    sock.close()
    return delay


def ping(destination, timeout=2, count=4):
    """
    Send >count< ping to >dest_addr< with the given >timeout< and display
    the result.
    """
    for i in range(count):
        # print ("ping %s..." % dest_addr,
        try:
            delay = do_one(destination, timeout)
        except socket.gaierror:
            print("nah")
            break

        if delay is None:
            print("failed. (timeout within %ssec.)" % timeout)
        else:
            delay = delay * 1000
            print("get ping in %0.4fms" % delay)
    # print


if __name__ == '__main__':
    ping("heise.de")
    ping("google.com")
    ping("a-test-url-taht-is-not-available.com")
    ping("192.168.1.1")
