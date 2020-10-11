#!/usr/bin/env python

# title       : dns
# description : simple dns proxy server with blocking support
# author      : Vitalii Levko
# date        : 20201011
# version     : 0.1
# usage       : ./dns.py


import argparse
import json
import socket
import sys


def _parse_arguments():
    # Parse optional arguments
    parser = argparse.ArgumentParser(
        description='Simple DNS Proxy Server with blocking support'
    )
    parser.add_argument(
        '-c', '--conf',
        nargs='?',
        default='config.json',
        type=argparse.FileType(),
        help='configuration file in JSON format; default is "config.json"'
    )
    parser.add_argument(
        '-s', '--serv',
        nargs='?',
        default='192.168.1.101',
        type=str,
        help='IP address of the server to be listening; default is "192.168.1.101"'
    )
    args = parser.parse_args()
    return args


def _load_configuration(conf):
    # Load configuration file
    try:
        configuration = json.load(conf)
        configuration['server']
        configuration['block']
        int(configuration['answer'], 2)
        if not len(configuration['answer']) == 4:
            raise
    except:
        print(f'[*] Error: unable to load JSON configuration from "{conf.name}"')
        sys.exit(1)
    return configuration


def _get_header_flags(flags, answ):
    # View RFC 1035 for details
    QR = '1'
    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(bytes(flags[0]))&(1<<bit))
    AA = '1'
    TC = RD = RA = '0'
    Z = '000'
    RCODE = answ
    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big') + int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')


def _get_domain_name_rtype(pack):
    # Extract domain name and rtype from the packet
    domain_name = []
    flag = length = i = j = 0
    section = ''
    for byte in pack:
        if flag == 0:
            flag = 1
            length = byte
            j += 1
            continue
        if byte != 0:
            section += chr(byte)
        i += 1
        if i == length:
            domain_name.append(section)
            section = ''
            flag = i = 0
        if byte == 0:
            domain_name.append(section)
            break
        j += 1
    rtype = pack[j:j+2]
    return (domain_name, rtype)


def _get_response_header(pack, answ):
    # View RFC 1035 for details
    transaction_id = pack[:2]
    flags = _get_header_flags(pack[2:4], answ)
    QDCOUNT = ANCOUNT = (1).to_bytes(2, byteorder='big')
    NSCOUNT = ARCOUNT = (0).to_bytes(2, byteorder='big')
    return transaction_id + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT


def _get_response_question(domain_name, rtype):
    # View RFC 1035 for details
    question = b''
    for section in domain_name:
        length = len(section)
        question += bytes([length])
        for character in section:
            question += ord(character).to_bytes(1, byteorder='big')
    question += rtype
    question += (1).to_bytes(2, byteorder='big')
    return question


def _get_response_answer(rtype):
    # View RFC 1035 for details
    body = b'\xc0\x0c'
    body += rtype
    body += (1).to_bytes(2, byteorder='big')
    body += (400).to_bytes(4, byteorder='big')
    ip_length = 16 if rtype == b'\x00\x1c' else 4
    body += (ip_length).to_bytes(2, byteorder='big')
    body += (0).to_bytes(ip_length, byteorder='big')
    return body


def _get_response(sock, pack, conf):
    # Check domain name, allow or deny a request
    domain_name, rtype = _get_domain_name_rtype(pack[12:])
    if '.'.join(domain_name[:-1]) in conf['block']:
        response = _get_response_header(pack, conf['answer'])
        response += _get_response_question(domain_name, rtype)
        response += _get_response_answer(rtype)
        return response
    try:
        sock.sendto(pack, (conf['server'], 53))
        response, addr = sock.recvfrom(512)
    except:
        print(f'[*] Error: unable to handle a request')
        sys.exit(1)
    return response


def _start_dns(serv, conf):
    # Listen port 53 of given IP address
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((serv, 53))
    print("[*] Listening Port 53")
    print(f"[*] Server IP Address {serv}")
    while 1:
        try:
            pack, addr = sock.recvfrom(512)
            resp = _get_response(sock, pack, conf)
            sock.sendto(resp, addr)
        except KeyboardInterrupt:
            break
        except:
            print('[*] Error: unable to resolve a DNS query')
            sys.exit(1)
    print('[*] Closing Connection')
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()


def _main():
    # Parse, load, start
    args = _parse_arguments()
    conf = _load_configuration(args.conf)
    _start_dns(args.serv, conf)


if __name__ == '__main__':
    # Entry point of DNS Proxy Server
    _main()
