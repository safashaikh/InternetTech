import argparse
import os
import nacl
from nacl.public import PrivateKey, Box

def generate_key_pair():
    private_key = PrivateKey.generate()
    private_key_hex = private_key.encode(encoder=nacl.encoding.HexEncoder)
    public_key = private_key.public_key
    public_key_hex = public_key.encode(encoder=nacl.encoding.HexEncoder)

    return private_key_hex, public_key_hex

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CS 352 Keychain Generator')
    parser.add_argument('-cf', '--client_filename', help='File to save the keychain for client', required=False)
    parser.add_argument('-sf', '--server_filename', help='File to save the keychain for server', required=False)
    parser.add_argument('-cd', '--client_address', help='Destination address for client', required=False)
    parser.add_argument('-cp', '--client_port', help='Destination port for client', required=False)
    parser.add_argument('-sd', '--server_address', help='Destination address for server', required=False)
    parser.add_argument('-sp', '--server_port', help='Destination port for server', required=False)

    args = vars(parser.parse_args())
    client_keychain_file = args['client_filename'] if args['client_filename'] else "keychain_client.txt"
    server_keychain_file = args['server_filename'] if args['server_filename'] else "keychain_server.txt"
    client_destination = args['client_address'] if args['client_address'] else "127.0.0.1"
    client_port = args['client_port'] if args['client_port'] else "9999"
    server_destination = args['server_address'] if args['server_address'] else "localhost"
    server_port = args['server_port'] if args['server_port'] else "8888"

    client_write_fd = open(client_keychain_file, "wb")
    server_write_fd = open(server_keychain_file, "wb")

    client_keys = generate_key_pair()
    server_keys = generate_key_pair()

    client_write_fd.write("private * * %s\n" % client_keys[0])
    server_write_fd.write("private * * %s\n" % server_keys[0])

    client_write_fd.write("public %s %s %s\n" % (server_destination, server_port, server_keys[1]))
    server_write_fd.write("public %s %s %s\n" % (client_destination, client_port, client_keys[1]))

    client_write_fd.close()
    server_write_fd.close()
