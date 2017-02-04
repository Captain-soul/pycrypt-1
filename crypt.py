import os
import sys
import common
import concurrent.futures
import multiprocessing
from multiprocessing import cpu_count
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

class Crypt(object):
    def __init__(self, file_name, thread_num = 2, level = common.Logger.LEVELS[1]):
        self._logger = common.Logger('Crypt', level)
        if not os.path.isfile(file_name):
            self._logger.error('File to be encrypted or decrypted not found.')
            raise FileNotFoundError('File to be encrypted or decrypted not found.')
        self._cpu_count = cpu_count()
        self._file_name = file_name
        self._thread_num = thread_num

    @property
    def thread_num(self):
        return self._thread_num

    @thread_num.setter
    def thread_num(self, value):
        if (not isinstance(value, int)) or value <= 0:
            self._logger.error('The number of threads must be positive integer.')
            raise ValueError('The number of threads must be positive integer.')
        if value > self._cpu_count:
            self._logger.warning('The number of threads is larger than the number of processors.')
        self._thread_num = value

class Encrypt(Crypt):
    def __init__(self, file_name, public_key_file_name, thread_num = 2, level = common.Logger.LEVELS[1]):
        Crypt.__init__(self, file_name, thread_num, level)
        self._logger = common.Logger('Encrypt', level)
        if not os.path.isfile(public_key_file_name):
            self._logger.error('Public key not found.')
            raise FileNotFoundError('Public key not found.')
        with open(public_key_file_name, 'r') as f:
            try:
                self._public_key = RSA.importKey(f.read())
            except ValueError:
                self._logger.error('Public key file format error.')
                raise ValueError('Public key file format error.')
        self._file_size = os.path.getsize(self._file_name)

    def __encrypt(self, output_file_name, pos, size = 40 * 1024 * 1024):
        # size = 1MB
        data = ''
        with open(self._file_name, 'rb') as f:
            f.seek(pos * size, os.SEEK_CUR)
            data = f.read(size)
        # 128 bit
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(self._public_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        with open(output_file_name, 'wb') as output_file:
            output_file.write(cipher_rsa.encrypt(session_key))
            cipher_text, tag = cipher_aes.encrypt_and_digest(data)
            output_file.write(cipher_aes.nonce)
            output_file.write(tag)
            output_file.write(cipher_text)

    def _encrypt(self, pos, size = 40 * 1024 * 1024):
        self.__encrypt(self._file_name + "_" + str(pos) + ".encrypted", pos, size)

    # def encrypt(self):
    def encrypt(self, size = 40 * 1024 * 1024, output_file_name = ""):
        # self._encrypt(output_file_name, pos, size)
        if output_file_name == '':
            output_file_name = self._file_name + ".encrypted"
        self._logger.info("Encrypt " + self._file_name + " to " + output_file_name)
        slice_num = self._file_size // size
        slice_num = slice_num if self._file_size % size == 0 else slice_num + 1
        if slice_num == 0:
            self._encrypt(output_file_name, 0)
        else:
            # pool = multiprocessing.Pool()
            tasks = [i for i in range(0, slice_num)]
            # append_process = multiprocessing.Process(target = self.merge, args = (slice_num, ))
            while tasks:
                tmp = tasks[0:8]
                tasks = tasks[8:]
                pool = []
                for item in tmp:
                    # pool.apply_async(self._encrypt, args = (self._file_name + "_" + str(item) + ".encrypted", item))
                    process = multiprocessing.Process(target = self._encrypt, args = (item, ))
                    process.start()
                    pool.append(process)
                [process.join() for process in pool]
            # pool.close()
            # pool.join()
            # append_process.start()
            # append_process.join()
            self.merge(slice_num)
        os.rename(self._file_name + "_0.encrypted", output_file_name)

    def merge(self, slice_num):
        append_file_name = self._file_name + "_0.encrypted"
        for i in range(1, slice_num):
            file_name = self._file_name + "_" + str(i) + ".encrypted"
            while not (os.path.exists(file_name) and ((i < (slice_num - 1) and os.path.getsize(file_name) ==
                common.size_40MB)
                    or (os.path.getsize(file_name) > 0))):
                pass
            with open(append_file_name, 'ab+') as f:
                with open(file_name, 'rb') as in_f:
                    f.write(in_f.read())
            os.remove(file_name)

class Decrypt(Crypt):
    def __init__(self, file_name, private_key_file_name, thread_num = 2, level = common.Logger.LEVELS[1]):
        Crypt.__init__(self, file_name, thread_num, level)
        self._logger = common.Logger('Decrypt', level)
        if not os.path.isfile(private_key_file_name):
            self._logger.error('Private key not found.')
            raise FileNotFoundError('Private key not found.')
        with open(private_key_file_name, 'r') as f:
            try:
                self._private_key = RSA.importKey(f.read())
            except ValueError:
                self._logger.error('Private key file format error.')
                raise ValueError('Private key file format error.')
        self._file_size = os.path.getsize(self._file_name)

    def _decrypt(self, output_file_name):
        # size = 1MB
        self._logger.info("Decrypt " + self._file_name)
        data = ''
        with open(self._file_name, 'rb') as f:
            encrypted_session_key, nonce, tag, cipher_text = [ f.read(x) for x in (self._private_key.size_in_bytes(),
                16, 16, -1) ]
            cipher_rsa = PKCS1_OAEP.new(self._private_key)
            session_key = cipher_rsa.decrypt(encrypted_session_key)
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(cipher_text, tag)
        with open(output_file_name, 'wb') as f:
            f.write(data)
        return data

    def __decrypt(self, b_str):
        encrypted_session_key = b_str[0 : self._private_key.size_in_bytes()]
        nonce = b_str[self._private_key.size_in_bytes() : self._private_key.size_in_bytes() + 16]
        tag = b_str[self._private_key.size_in_bytes() + 16 : self._private_key.size_in_bytes() + 32]
        cipher_text = b_str[self._private_key.size_in_bytes() + 32:]
        cipher_rsa = PKCS1_OAEP.new(self._private_key)
        try:
            session_key = cipher_rsa.decrypt(encrypted_session_key)
        except TypeError:
            self._logger.error('This is not a private key.')
            # raise TypeError('This is not a private key.')
            sys.exit(1)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        return cipher_aes.decrypt_and_verify(cipher_text, tag)

    def _split(self, pos, size = common.size_40MB):
        with open(self._file_name, 'rb') as in_f:
            with open(os.path.splitext(self._file_name)[0] + "_" + str(pos) + ".decrypted", 'wb') as f:
                in_f.seek(pos * size, os.SEEK_CUR)
                f.write(self.__decrypt(in_f.read(size)))

    # def decrypt(self):
    def decrypt(self, output_file_name, size = common.size_40MB):
        # self._decrypt(output_file_name)
        self._logger.info("Decrypt " + self._file_name + " to " + output_file_name)
        slice_num = self._file_size // size
        slice_num = slice_num if self._file_size % size == 0 else slice_num + 1
        if slice_num == 0:
            self._decrypt(output_file_name)
            return
        tasks = [i for i in range(slice_num)]
        while tasks:
            tmp = tasks[0:8]
            tasks = tasks[8:]
            pool = []
            for i in tmp:
                process = multiprocessing.Process(target = self._split, args = (i, ))
                pool.append(process)
                process.start()
            [process.join() for process in pool]
        self.merge(slice_num)
        base = os.path.splitext(self._file_name)[0]
        os.rename(base + "_0.decrypted", output_file_name)

    def merge(self, slice_num):
        base = os.path.splitext(self._file_name)[0]
        append_file_name = base + "_0.decrypted"
        for i in range(1, slice_num):
            file_name = base + "_" + str(i) + ".decrypted"
            with open(append_file_name, 'ab+') as f:
                with open(file_name, 'rb') as in_f:
                    f.write(in_f.read())
            os.remove(file_name)

if __name__ == '__main__':
    # 加密后大小: 41943328 Bytes
    # e = Encrypt('../Desktop/fsx.mkv', '/home/user/.ssh/id_rsa.pub')
    # e.encrypt()
    # e = Encrypt('../Desktop/OReilly.Programming.Computer.Vision.With.Python.Jun.2012.ISBN.1449316549.pdf', '/home/user/.ssh/id_rsa.pub')
    # e.encrypt()
    e = Encrypt('./huffman.py', '/home/user/.ssh/id_rsa.pub')
    e.encrypt()
    d = Decrypt('./huffman.py.encrypted', '/home/user/.ssh/id_rsa')
    d.decrypt('huffman.txt')
    # d = Decrypt('../Desktop/fsx.mkv.encrypted', '/home/user/.ssh/id_rsa')
    # d.decrypt('fsx.mkv')
    # d = Decrypt('../Desktop/OReilly.Programming.Computer.Vision.With.Python.Jun.2012.ISBN.1449316549.pdf.encrypted', '/home/user/.ssh/id_rsa')
    # d.decrypt('OReilly.Programming.Computer.Vision.With.Python.Jun.2012.ISBN.1449316549.pdf')
