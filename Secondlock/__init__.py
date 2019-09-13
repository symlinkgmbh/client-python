# Copyright 2018-2019 Symlink GmbH
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.                                                                                                       

from   Crypto.Util.Padding    import pad, unpad
from   Crypto.PublicKey       import RSA
from   Crypto.Cipher          import AES, PKCS1_OAEP
from   Crypto.Hash            import SHA512
from   dateutil               import tz
from   datetime               import datetime, timedelta
from   sha3                   import sha3_512
import json
import time
import string
import random
import base64
import hashlib
import requests
import dns.resolver

class SecondLock():

    def __init__(self, secondlock_username, secondlock_password):
        self._secondlock_username                    = secondlock_username
        self._secondlock_password                    = secondlock_password
        self._headers                                = None
        self._secondlock_host, self._secondlock_port = self._getSecondLockServerForEmail(self._secondlock_username)

    ############################################
    ## Network related functions              ##
    ############################################

    def _getSecondLockServerForEmail(self, email):
        domain = email.split('@')[1]

        # Fallback if there is no SRV record
        secondlock_host_name = 'community.2ndlock.org'
        secondlock_host_port = 443
        resolver             = dns.resolver.Resolver()
        resolver.timeout     = 5
        resolver.lifetime    = 5

        try:
            srv_records          = resolver.query('_2ndlock._tcp.'+domain, 'SRV')
            secondlock_host_name = str(srv_records[0].target).rstrip('.')
            secondlock_host_port = srv_records[0].port
        except:
            print("No SRV record for your Doamin (%s), using 2ndLock Community Server instead." % domain)

        return secondlock_host_name, secondlock_host_port

    def _loginSecondLockServer(self):
        self._headers = {"Content-Type": "application/json"}
        payload       = json.dumps({"email": self._secondlock_username  , "password": self._secondlock_password})
        response      = requests.request("POST", "https://%s:%d/api/v1/authenticate" % (self._secondlock_host, self._secondlock_port), data=payload, headers=self._headers, timeout=5)

        if response.status_code == 200:
            api_token = json.loads(response.content.decode('utf-8'))['token']
            self._headers['Authorization'] = 'Bearer {0}'.format(api_token)
        else:
            error_message = json.loads(response.content.decode('utf-8'))
            raise Exception("Error logging into server (%s): %s" % (error_message['error']['code'], error_message['error']['message']))

    def _uploadRSAPublicKeyToSecondLockServer(self):

        if self._headers == None:
            self._loginSecondLockServer()

        payload  = json.dumps({"pubKey": self._rsa_short_public_key, "deviceId": self._device_id , "email": self._secondlock_username})
        response = requests.request("POST", "https://%s:%d/api/v1/key" % (self._secondlock_host, self._secondlock_port), data=payload, headers=self._headers, timeout=5)

        if response.status_code != 200:
            error_message = json.loads(response.content.decode('utf-8'))
            raise Exception("Error uploading RSA public key to 2ndLock Server (%s): %s" % (error_message['error']['code'], error_message['error']['message']))

    def _uploadContentKeyToSecondLockServer(self, checksum, contentkey, email, live_time_in_days=23):

        if self._headers == None:
            self._loginSecondLockServer()

        format_string   = "%a %b %d %Y %H:%M:%S GMT%z"
        datetime_object = datetime.now().replace(tzinfo=tz.tzlocal())
        new_date        = datetime_object + timedelta(days=live_time_in_days)
        new_date_string = datetime.strftime(new_date, format_string)
        payload         = json.dumps({"checksum": checksum.decode("utf-8") , "key": contentkey.decode("utf-8") , "domain": email.split('@')[1], "liveTime": new_date_string})
        response        = requests.request("POST", "https://%s:%d/api/v1/content" % (self._secondlock_host, self._secondlock_port), data=payload, headers=self._headers, timeout=5)

        if response.status_code != 200:
            error_message = json.loads(response.content.decode('utf-8'))
            raise Exception("Error uploading Contentkey to 2ndLock Server (%s): %s" % (error_message['error']['code'], error_message['error']['message']))

    def _getPublicKeysForUser(self, email):

        if self._headers == None:
            self._loginSecondLockServer()

        response = requests.request("GET", "https://%s:%d/api/v1/key/%s" % (self._secondlock_host, self._secondlock_port, email), headers=self._headers, timeout=5)

        if response.status_code == 200:
            return json.loads(response.content.decode("utf-8"))
        else:
            error_message = json.loads(response.content.decode('utf-8'))
            raise Exception("Error requesting public keys for user %s on 2ndLock Server (%s): %s" % (email, error_message['error']['code'], error_message['error']['message']))

    def _getContentKeyForFile(self, content_sha_and_device_id_base64):

        if self._headers == None:
            self._loginSecondLockServer()

        response = requests.request("GET", "https://%s:%d/api/v1/content/%s" % (self._secondlock_host, self._secondlock_port, content_sha_and_device_id_base64.decode()) , headers=self._headers, timeout=5)

        if response.status_code == 200:
            rsa_encrypted_base64 = json.loads(response.content.decode('utf-8'))['key']
            return base64.b64decode(rsa_encrypted_base64)
        else:
            error_message = json.loads(response.content.decode('utf-8'))
            raise Exception("Error requesting content keys on 2ndLock Server (%s): %s" % (error_message['error']['code'], error_message['error']['message']))

    ##################################
    ## Encryption related functions ##
    ##################################

    def _generateNewRSAKey(self, rsa_key_length, passphrase):
        self._rsa_key                      = RSA.generate(rsa_key_length)
        self._rsa_private_key_string       = self._rsa_key.exportKey(passphrase=passphrase, format='PEM', pkcs=8, protection="scryptAndAES128-CBC")
        self._rsa_public_key_string        = self._rsa_key.publickey().exportKey(format='PEM')
        self._processPrivateRSAKey(passphrase)
        self._processPublicRSAKey()

    def _processPrivateRSAKey(self, passphrase):
        self._rsa_short_private_key = self._rsa_private_key_string.decode('utf-8')[37:-34].replace("\n","")
        self._rsa_private_key       = RSA.import_key(self._rsa_private_key_string, passphrase=passphrase)
        self._rsa_cipher            = PKCS1_OAEP.new(self._rsa_private_key, hashAlgo = SHA512)

        mysha512                    = hashlib.sha512()
        mysha512.update(self._rsa_short_private_key.encode("utf-8"))
        self._device_id             = mysha512.hexdigest()

    def _processPublicRSAKey(self):
        self._rsa_short_public_key  = self._rsa_public_key_string.decode('utf-8')[27:-25].replace("\n","")

    def _AESEncryptContent(self, content):
        aes_key               = str.encode(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32)))
        aes_iv                = str.encode(''.join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16)))
        aes_concatinated_key  = aes_key+aes_iv
        aes_cipher            = AES.new(aes_key, AES.MODE_CBC, iv = aes_iv)
        encrypted_content     = aes_cipher.encrypt(pad(content, AES.block_size))
        encrypted_content_sha = str(sha3_512(encrypted_content).hexdigest()).upper()
        return encrypted_content, encrypted_content_sha, aes_concatinated_key

    def _AESDecryptContent(self, aes_key, aes_iv, encrypted_content):
        aes_cipher      = AES.new(aes_key, AES.MODE_CBC, iv = aes_iv)
        unciphered_data = unpad(aes_cipher.decrypt(encrypted_content), AES.block_size)
        return unciphered_data

    def _RSAEncryptContent(self, pubkey_string, aes_concatinated_key, encrypted_content_sha, device_id):
        pem_string                       = "-----BEGIN PUBLIC KEY-----\n" + pubkey_string + "\n-----END PUBLIC KEY-----\n"
        rsa_public_key                   = RSA.import_key(pem_string)
        cipher_rsa                       = PKCS1_OAEP.new(rsa_public_key, hashAlgo = SHA512)
        rsa_encrypted                    = cipher_rsa.encrypt(aes_concatinated_key)
        rsa_encrypted_base64             = base64.b64encode(rsa_encrypted)
        content_sha_and_devide_id_string = encrypted_content_sha + device_id
        content_sha_and_device_id_sha    = sha3_512(content_sha_and_devide_id_string.encode('utf-8')).hexdigest().upper()
        content_sha_and_device_id_base64 = base64.b64encode(content_sha_and_device_id_sha.encode("utf-8"))
        return content_sha_and_device_id_base64, rsa_encrypted_base64

    def _RSADecryptContent(self, rsa_encrypt):
        rsa_decrypted   = self._rsa_cipher.decrypt(rsa_encrypt).decode()
        aes_key         = str.encode(rsa_decrypted[:32])
        aes_iv          = str.encode(rsa_decrypted[32:])
        return aes_key, aes_iv

    ######################
    ## Public functions ##
    ######################

    def generateKeyPair(self, passphrase, rsa_key_length=2**12):

        if rsa_key_length < 2**12:
            raise Exception("Key length to small")

        self._generateNewRSAKey(rsa_key_length, passphrase)
        self._uploadRSAPublicKeyToSecondLockServer()
        return self._rsa_private_key_string, self._rsa_public_key_string

    def importPrivateKey(self, passphrase, private_key_string):
        self._rsa_private_key_string = private_key_string
        self._processPrivateRSAKey(passphrase)

    def importPublicKey(self, public_key_string):
        self._rsa_public_key_string = public_key_string
        self._processPublicRSAKey()

    def encrypt(self, input_file_content, email, live_time_in_days = 365):

        if live_time_in_days < 1:
            raise Exception("Live time should be at least 1 day")

        encrypted_content, encrypted_content_sha, aes_concatinated_key = self._AESEncryptContent(input_file_content)

        for device_entry in self._getPublicKeysForUser(email):
            device_id                                              = device_entry['deviceId']
            pubkey_string                                          = device_entry['pubKey']
            content_sha_and_device_id_base64, rsa_encrypted_base64 = self._RSAEncryptContent(pubkey_string, aes_concatinated_key, encrypted_content_sha, device_id)
            self._uploadContentKeyToSecondLockServer(content_sha_and_device_id_base64, rsa_encrypted_base64, email, live_time_in_days)

        return encrypted_content

    def decrypt(self, encrypted_content):

        if not hasattr(self, '_rsa_cipher'):
            raise Exception("No private RSA key loaded")

        encrypted_content_sha            = str(sha3_512(encrypted_content).hexdigest()).upper()
        content_sha_and_devide_id_string = encrypted_content_sha + self._device_id
        content_sha_and_device_id_sha    = sha3_512(content_sha_and_devide_id_string.encode('utf-8')).hexdigest().upper()
        content_sha_and_device_id_base64 = base64.b64encode(content_sha_and_device_id_sha.encode("utf-8"))
        rsa_encrypt                      = self._getContentKeyForFile(content_sha_and_device_id_base64)
        aes_key, aes_iv                  = self._RSADecryptContent(rsa_encrypt)
        content                          = self._AESDecryptContent(aes_key, aes_iv, encrypted_content)
        return content
