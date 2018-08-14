import os
import sys
import socket
import struct
import time

# constants for use in making and receiving ICMP messages
ICMP_REQUEST_TYPE = 8
ICMP_REPLY_TYPE = 0
ICMP_CODE = 0


def to_digit(value):
    """ Converts a value to be numeric
    :param value: the value to be converted to a number
    :return: the value itself it is already a number, else the
            numeric form of the value
    """
    if isinstance(value, int):
        return value

    return ord(value)


def checksum(source):
    """ Calculates a checksum for source to be used in network communications
    :param source: the input to calculate the checksum for
    :return: the calculated checksum
    """
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


def receive_one_ping(sock, timeout):
    """ Received a ping from the given scoket
    :param sock: the socket to receive the ping from
    :param timeout: the time after which to stop waiting for a ping to be received
    :return: a tuple containing the total time taken to receive the response and
            the received ping packet
    """
    sock.settimeout(timeout)
    try:
        start_time = time.clock()
        data, _ = sock.recvfrom(1024)
        end_time = time.clock()
    except socket.timeout:
        print("Request timed out")
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
    """ Sends a single ping packet to the given destination via the socket
    :param sock: the socket to send the ping over
    :param destination: the host to send the ping to
    :param process_id: the ID of the ping
    :param sequence_num: the sequence number of the ping
    """
    destination = socket.gethostbyname(destination)

    # Header is: type (8), code (8), checksum (16), id (16), sequence (16)

    icmp_checksum = 0

    # Make a dummy header with a 0 checksum.
    header = struct.pack("BBHHH", ICMP_REQUEST_TYPE, ICMP_CODE, icmp_checksum, process_id,
                         sequence_num)

    # Calculate the checksum on the data and the dummy header.
    icmp_checksum = checksum(header)

    # Now that we have the right checksum, we put that in
    header = struct.pack("BBHHH", ICMP_REQUEST_TYPE, ICMP_CODE, icmp_checksum, process_id,
                         sequence_num)

    sock.sendto(header, (destination, 1))  # port number is not relevant for ICMP


def do_one(destination, timeout, sequence_num):
    """ Completes an entire ping packet send/receive and returns the time taken for this process
    :param destination: the host to ping
    :param timeout: the maximum time to wait for a response to the ping
    :param sequence_num: the sequence number of the ping
    :return: the time taken to complete the ping or None on timeout
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error:
        print("oops")
        sys.exit()

    process_id = os.getpid() & 0xFFFF

    send_one_ping(sock, destination, process_id, sequence_num)
    delay = receive_one_ping(sock, timeout)

    sock.close()
    return delay


def traceroute(destination, max_hops=50, timeout=1):
    """ Calculates the number of hops required to reach the given destination
    :param destination: the hostname being traced
    :param max_hops: the max number of hops to be completed
    :param timeout: the max time to wait for a response after sending a packet
    :return: a tuple containing the number of hops and the time taken to complete
            the final hop
    """
    ttl = 1
    start_time = 0
    end_time = 0
    while ttl < max_hops:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        except socket.error:
            print("oh no")
            sys.exit()

        destination = socket.gethostbyname(destination)
        icmp_checksum = 0
        header = struct.pack("BBHHH", ICMP_REQUEST_TYPE, ICMP_CODE, icmp_checksum, 0, 0)
        icmp_checksum = checksum(header)
        header = struct.pack("BBHHH", ICMP_REQUEST_TYPE, ICMP_CODE, icmp_checksum, 0, 0)

        sock.sendto(header, (socket.gethostbyname(destination), 1))

        try:
            start_time = time.clock()
            data, address = sock.recvfrom(1024)
            end_time = time.clock()
        except socket.timeout:
            ttl += 1
            continue
        except socket.error:
            print("this is fine")
            sys.exit()
        finally:
            sock.close()

        if address:
            if address[0] == destination:
                break

        ttl += 1

    return ttl, end_time - start_time


def ping(destination, timeout=1, count=3):
    """ Sends the given count of ICMP ping packets to the destination
    :param destination: the hostname to ping
    :param timeout: the maximum time to wait for a response from the host being pinged
    :param count: the number of pings to send
    :return: total time taken to complete all pings
    """
    total_time = 0

    for i in range(count):
        total_time += do_one(destination, timeout, i)[0]

    return total_time


def main():
    """
    Demonstrates usage of the above functions
    """
    
    args = sys.argv
    if len(args) != 2:
        print("Usage: python pyping.py hostname")
        sys.exit()

    host = args[1]
    print("Pyping by E. Bennett\n")

    try:
        ip = socket.gethostbyname(host)
    except socket.error:
        print("Not a valid host name")
        sys.exit()

    print("Sending 3 pings to {0}, IP {1}".format(host, ip))

    total_time = ping(host)
    num_hops, time_taken = traceroute(host)

    total_time += time_taken
    average_time = round((total_time * 1000) / 3)

    print("3 replies received with average {0}ms, {1} hops".format(average_time, num_hops))


if __name__ == '__main__':
    main()
