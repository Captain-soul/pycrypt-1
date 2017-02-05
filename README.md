## pycrypt
### main idea
- Encryption
   - divide a file to fragments
   - generate 16 random bytes for 128 bits AES key
   - use RSA public key to encrypt AES key
   - use AES key to encrypt files
- Decryption
   - divide an encrypted file to fragments
   - use RSA private key to decrypt AES key
   - use AES key to decrypt files

### usage
```bash
sudo pip install -r requirements.txt 
./pycrypt -h
```