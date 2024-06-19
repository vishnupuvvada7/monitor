def hex_packet_decoder(hex_data):
    lines = hex_data.strip().split('\n')
    decoded_packets = []

    for line in lines:
        if line.strip():  # Skip empty lines
            parts = line.split()
            if len(parts) >= 17:
                hex_bytes = ''.join(parts[2:])  # Skip the index and join hex bytes
                try:
                    ascii_chars = ''.join([chr(int(hex_bytes[i:i+2], 16)) for i in range(0, len(hex_bytes), 2)])
                    decoded_packets.append(ascii_chars)
                except ValueError:
                    # Handle invalid hex bytes (optional)
                    pass

    return decoded_packets


# Example hex packet data (replace with your actual data)
hex_data = """
00 1f e6 2c 4e d0 84 69 93 9e 06 c8 08 00 45 00
02 8d 64 cc 40 00 80 06 af eb c0 a8 01 9d 17 2c
0a 42 dc b6 01 bb 55 cb 08 ec 26 f2 3a d0 50 18
02 00 04 c4 00 00 cd 52 24 8f 2d a7 91 12 29 5e
58 c7 e4 2e 42 9b 02 71 14 00 12 00 00 00 10 00
0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31 00
0a 00 0c 00 0a fa fa 63 99 00 1d 00 17 00 18 00
2b 00 07 06 9a 9a 03 04 03 03 00 1b 00 03 02 00
02 00 17 00 00 00 23 00 00 00 2d 00 02 01 01 fe
0d 00 ba 00 00 01 00 01 a2 00 20 96 b6 6d 37 3f
0b 10 2e 50 e4 fa 48 97 c5 65 5b b9 c2 59 43 b4
7d 0c 3e f5 b2 5b d9 ea bd 18 79 00 90 de e5 1c
57 58 99 28 d7 22 ac 3f 94 be f1 a3 a6 35 3a f8
83 94 84 10 6b 12 26 ba 3c 9a d6 73 24 6d bb f0
e4 40 a3 f5 27 ce 12 25 53 bf 24 55 89 d9 19 e5
5f 11 da d4 a0 76 44 5e c1 ee 9f a8 18 5b b0 7b
22 1b e1 ef 40 5e 92 9a 4a 05 25 51 15 47 15 f2
51 55 a5 f3 6a 03 76 c7 62 cb cb 34 11 7c d2 61
1c 2d ab 63 b3 f3 22 e3 83 d5 a3 81 64 c4 0f 2a
88 28 e3 5c 71 e1 e0 3c 62 3b fd 4b 22 90 d9 8c
6f 15 39 e0 9f 2d 1a 1c a7 e7 04 b3 2f 00 00 00
11 00 0f 00 00 0c 77 77 77 2e 62 69 6e 67 2e 63
6f 6d ff 01 00 01 00 8a 8a 00 01 00 00 29 01 2b
00 f6 00 f0 00 01 51 1f ca 7a 08 84 63 47 4b 46
47 27 57 a6 1c 59 b2 4e 31 00 13 5a c4 46 5e 00
24 6c a2 08 9d 42 c5 41 17 30 23 11 81 e0 0e 0e
10 6b 11 d4 4a f4 4c 90 8a 23 be 2b 8c dc d8 62
e6 c3 c4 4c cb 69 66 77 fb 95 9d bf 77 c6 77 62
e3 97 e0 39 5b c1 a5 fb 2c fb 59 48 4e 82 3e 05
66 e2 28 95 e6 6b 38 e4 ee 0d e5 28 1e 4a a6 27
4f 36 86 08 83 83 2e a9 f4 a7 c0 9c 68 9f ec cd
a1 d6 4d 54 f0 0b 40 b5 79 bd bb 15 81 36 69 71
47 a2 e1 ff 02 7f 17 c8 d6 d1 d3 a6 e6 ae 8c 58
10 ef 9d 0c d6 ac 99 4c 4e 34 8e c3 a7 61 f6 c5
27 44 78 ba 30 0b 04 14 60 23 c3 d2 0f eb fc 86
22 12 c1 6f 1b e1 9f 89 49 2b 6b cf c8 12 6c b9
73 0d 51 82 59 b5 2c 0e 04 d2 67 2f d3 7b 15 4d
62 73 27 2e 40 77 47 ae 3e 37 ca 2d 9e ed f2 70
b2 f1 fa a9 ae 12 c3 16 00 31 30 f7 1c 0b 7a fd
1a f2 36 e5 87 c7 33 08 0a 19 73 bc c0 ac be 0b
af 49 8d 31 87 cb 0d fe cf d2 91 bb c0 fd b5 56
6c 99 1c 6d 74 5b 04 ea a8 cd 8f
"""

decoded_result = hex_packet_decoder(hex_data)
print(decoded_result)  # Print the decoded packets
