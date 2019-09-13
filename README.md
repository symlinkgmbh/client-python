# Python lib and CLI for 2ndLock

## Requirements
See requirements.txt

## Library
For python 3. Supports 
  * Key generation
  * Key import
  * Encryption
  * Decryption

## CLI
Use command line to interact with 2ndLock with scripts or interactive

### Example
Use 2ndLock Community Server at https://community.2ndlock.org for testing.

```bash
pip install cli42ndLock

cli42ndlock generate-keys test@example.com my_passwd my_passphrase_for_key my_private_key.pem

cli42ndlock encrypt test@example.com my_passwd testfile.txt testfile.2ndlock recipient@example.com

cli42ndlock decrypt recipient@example.com my_passwd my_passphrase_for_key testfile.2ndlock testfile.new my_private_key.pem 
```

## License
[Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0)
