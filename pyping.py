import os
import sys
import socket
import struct
import time

ICMP_REQUEST_TYPE = 8
ICMP_REPLY_TYPE = 0
ICMP_CODE = 0


def to_digit(value):
    if isinstance(value, int):
        return value

    return ord(value)


def checksum(source):
    checksum_return = 0
    length = len(source)

    for char in range(0, length, 2):
        if char + 1 == length:
            checksum_return += to_digit(source[char])
            break
        checksum_return += (to_digit(source[char + 1]) << 8) + to_digit(source[char])

    checksum_return = (checksum_return >> 16) + (checksum_return & 0xffff)
    checksum_return += (checksum_return >> 16)
    checksum_return = ~checksum_return

    return checksum_return & 0xffff


def receive_one_ping(sock, process_id, timeout):
    """
    receive the ping from the socket.
    """
    sock.settimeout(timeout)
    try:
        start_time = time.clock()
        data, _ = sock.recvfrom(1024)
        end_time = time.clock()
    except socket.timeout:
        print("timeout lmao")
        sys.exit()
    except socket.error:
        print("not good lol")
        sys.exit()
    finally:
        sock.close()

    header = data[20:28]
    unpacked = struct.unpack("BBHHH", header)
    total_time = end_time - start_time

    return total_time, unpacked


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

    # Calculate the checksum on the data and the dummy header.
    icmp_checksum = checksum(header)

    # Now that we have the right checksum, we put that in
    # socket.htons
    header = struct.pack("BBHHH", ICMP_REQUEST_TYPE, ICMP_CODE, icmp_checksum, process_id,
                         sequence_num)

    sock.sendto(header, (destination, 1))  # port number is not relevant for ICMP


def do_one(dest_addr, timeout, sequence_num):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error:
        print("oops")
        sys.exit()

    process_id = os.getpid() & 0xFFFF

    send_one_ping(sock, dest_addr, process_id, sequence_num)
    delay = receive_one_ping(sock, process_id, timeout)

    sock.close()
    return delay


def ping(destination, timeout=1, count=3):
    """
    Send >count< ping to >dest_addr< with the given >timeout< and display
    the result.
    """
    print(do_one(destination, timeout, 1))
    # for i in range(count):
    #     # print ("ping %s..." % dest_addr,
    #     try:
    #         delay = do_one(destination, timeout)
    #     except socket.gaierror:
    #         print("nah")
    #         break
    #
    #     if delay is None:
    #         print("failed. (timeout within %ssec.)" % timeout)
    #     else:
    #         delay = delay * 1000
    #         print("get ping in %0.4fms" % delay)
    # print


if __name__ == '__main__':
    ping("uq.edu.au")
