# Bootloader Design

# Load Firmware
 
1. Receive, decrypt, and verify header (RSA)
2. Receive and decrypt body if verification passes
3. Check for correct version number (no drop-down attacks)
4. Further user credential check?
5. Update version number
6. Put in correct location

