#!/usr/bin/env python

"""
Minimal implementation of the KeePassXC data format. This was only implemented to see how it's working
and should NOT be used on important data!!! Basically everything is based on the official documentation
at [1]. External libraries are used for the cryptography.

[1] https://keepass.info/help/kb/kdbx.html
"""

__author__ = 'Martin Wichmann'
__license__ = 'MIT'
__version__ = '0.0.1'

import argparse
import base64
import codecs
import ctypes
import hashlib
import hmac
import io
import struct
import xml.etree.ElementTree as ET
import zlib

import argon2
from Crypto.Cipher import AES, ChaCha20, Salsa20


KDBX_HEADER_SIGNATURE_1 = 0x9AA2D903
KDBX_HEADER_SIGNATURE_2 = 0xB54BFB67
KDBX_HEADER_FORMAT_VERSION_4 = 0x00040000
KDBX_HEADER_FORMAT_VERSION_4_1 = 0x00040001

KDBX_HEADER_FIELD_ID_EOH = 0
KDBX_HEADER_FIELD_ID_ENCRYPTION_ALGORITHM = 2
KDBX_HEADER_FIELD_ID_COMPRESSION_ALGORITHM = 3
KDBX_HEADER_FIELD_ID_MASTER_SALT = 4
KDBX_HEADER_FIELD_ID_IV_NONCE = 7
KDBX_HEADER_FIELD_ID_KDF_PARAMS = 11
KDBX_HEADER_FIELD_ID_CUSTOM_DATA = 12

KDBX_ENCRYPTION_ALGORITHM_AES256 = codecs.decode('31C1F2E6BF714350BE5805216AFC5AFF', 'hex')
KDBX_ENCRYPTION_ALGORITHM_CHACHA20 = codecs.decode('D6038A2B8B6F4CB5A524339A31DBB59A', 'hex')
KDBX_ENCRYPTION_ALGORITHM_TWOFISH = codecs.decode('AD68F29F576F4BB9A36AD47AF965346C', 'hex')

KDBX_COMPRESSION_ALGORITHM_NO = 0
KDBX_COMPRESSION_ALGORITHM_GZIP = 1

KDBX_VARDICT_KDF_UUID = codecs.encode('$UUID')
KDBX_VARDICT_KDF_S = codecs.encode('S')
KDBX_VARDICT_KDF_R = codecs.encode('R')
KDBX_VARDICT_KDF_V = codecs.encode('V')
KDBX_VARDICT_KDF_I = codecs.encode('I')
KDBX_VARDICT_KDF_M = codecs.encode('M')
KDBX_VARDICT_KDF_P = codecs.encode('P')

KDBX_KDF_ALGORITHM_AES = codecs.decode('C9D9F39A628A4460BF740D08C18A4FEA', 'hex')
KDBX_KDF_ALGORITHM_ARGON2D = codecs.decode('EF636DDF8C29444B91F7A9A403E30A0C', 'hex')
KDBX_KDF_ALGORITHM_ARGON2ID = codecs.decode('9E298B1956DB4773B23DFC3EC6F0A1E6', 'hex')

KDBX_INNER_HEADER_FIELD_ID_EOH = 0
KDBX_INNER_HEADER_FIELD_ID_ENCRYPTION_ALGORITHM = 1
KDBX_INNER_HEADER_FIELD_ID_ENCRYPTION_KEY = 2
KDBX_INNER_HEADER_FIELD_ID_BINARY_CONTENT = 3

KDBX_INNER_HEADER_ENCRYPTION_ALGORITHM_SALSA20 = 2
KDBX_INNER_HEADER_ENCRYPTION_ALGORITHM_CHACHA20 = 3

KDBX_INNER_HEADER_ENCRYPTION_SALSA20_NONCE = bytes([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A])


def var_structure(size_member=None):
    """
    Adds classmethod _create_var_structure(_cls, n) that dynamically resizes last structure member
    and __new__ that directly reads bytes/file into object using dynamic sizing.
    """
    def _var_structure(cls):
        def __new__(cls, data=None):
            if data is None:
                return cls._create_var_structure(0)()
            elif isinstance(data, bytes):
                size = getattr(cls.from_buffer_copy(data), size_member) if size_member is not None else 0
                return cls._create_var_structure(size).from_buffer_copy(data)
            elif isinstance(data, io.IOBase):
                pos = data.tell()
                obj = cls._create_var_structure(0)()
                data.readinto(obj)
                size = getattr(obj, size_member) if size_member is not None else 0
                data.seek(pos)
                obj = cls._create_var_structure(size)()
                data.readinto(obj)
                return obj
            else:
                raise ValueError()

        @classmethod
        def _create_var_structure(_cls, n):
            tmp = _cls._fields_ if size_member is None else _cls._fields_[:-1] + [(_cls._fields_[-1][0], _cls._fields_[-1][1]._type_ * n)]
            return type(_cls.__name__, _cls.__bases__, {
                '_fields_': tmp,
                '_pack_': _cls._pack_ if hasattr(_cls, '_pack_') else 0,
                '_align_': _cls._align_ if hasattr(_cls, '_align_') else 0
            })

        cls.__new__ = __new__
        cls._create_var_structure = _create_var_structure       # no dunder to avoid name mangling
        return cls
    return _var_structure


@var_structure()
class HeaderRaw(ctypes.LittleEndianStructure):
    _fields_ = [('signature_1', ctypes.c_uint32),
                ('signature_2', ctypes.c_uint32),
                ('format_version', ctypes.c_uint32)]
    _pack_ = 1

@var_structure('size')
class HeaderFieldRaw(ctypes.LittleEndianStructure):
    _fields_ = [('id', ctypes.c_uint8),
                ('size', ctypes.c_int32),
                ('data', ctypes.c_uint8 * 0)]
    _pack_ = 1

@var_structure()
class VariantDictHeader(ctypes.LittleEndianStructure):
    _fields_ = [('format_version', ctypes.c_uint16)]

@var_structure('r')
class VariantDictFieldTop(ctypes.LittleEndianStructure):
    _fields_ = [('t', ctypes.c_uint8),
                ('r', ctypes.c_int32),
                ('U', ctypes.c_uint8 * 0)]
    _pack_ = 1

@var_structure('s')
class VariantDictFieldBottom(ctypes.LittleEndianStructure):
    _fields_ = [('s', ctypes.c_int32),
                ('V', ctypes.c_uint8 * 0)]
    _pack_ = 1

@var_structure()
class VariantDictFooter(ctypes.LittleEndianStructure):
    _fields_ = [('null', ctypes.c_uint8)]
    _pack_ = 1

@var_structure('s')
class BlockData(ctypes.LittleEndianStructure):
    _fields_ = [('hmac', ctypes.c_uint8 * 32),
                ('s', ctypes.c_int32),
                ('data', ctypes.c_uint8 * 0)]
    _pack_ = 1

@var_structure('s')
class InnerHeaderField(ctypes.LittleEndianStructure):
    _fields_ = [('t', ctypes.c_uint8),
                ('s', ctypes.c_int32),
                ('V', ctypes.c_uint8 * 0)]
    _pack_ = 1


class KdbxFileSignatureError(Exception):
    pass

class KdbxFormatVersionError(Exception):
    pass

class KdbxParseError(Exception):
    pass

class KdbxUnknownKdfAlgorithmError(Exception):
    pass

class KdbxUnknownEncryptionAlgorithmError(Exception):
    pass

class KdbxUnsupportedEncryptionAlgorithmError(Exception):
    pass

class KdbxUnknownCompressionAlgorithmError(Exception):
    pass

class KdbxHeaderIntegrityError(Exception):
    pass

class KdbxDataIntegrityError(Exception):
    pass

class KdbxUnknownInnerHeaderfieldError(Exception):
    pass


def unpack_uint32(data):
    return struct.unpack('<I', data)[0]

def unpack_uint64(data):
    return struct.unpack('<Q', data)[0]

def pack_uint32(data):
    return struct.pack('<I', data)

def pack_uint64(data):
    return struct.pack('<Q', data)


class KdbxFile(object):
    def __init__(self, file_path, password, keyfile_data=None, keyprovider_data=None, dpapi_data=None):
        with open(file_path, 'rb') as fd:
            self._kdbx_parse_header(fd)
            self._kdbx_calculate_keys(password, keyfile_data, keyprovider_data, dpapi_data)
            self._kdbx_check_header_integrity()
            self._kdbx_read_block_data(fd)
            self._kdbx_decrypt_data()
            self._kdbx_decompress_data()
            self._kdbx_parse_inner_header()
            self._kdbx_parse_xml()
            self._kdbx_decrypt_process_memory_protection()

    def __str__(self):
        ret = f'# KDBXFile: {self._xparse_get_dbname()}\n'
        for entry in self._xparse_get_entries():
            ret += f'{entry['title']}\n'
            ret += f'  username: {entry['username']}\n'
            ret += f'  password: {entry['password']}\n'
            ret += f'  binaries: {len(entry['binaries'])} files\n'
        ret = ret[:-1]
        return ret

    def _kdbx_parse_header(self, fd):
        # Parse file ID
        header_raw = HeaderRaw(fd)

        if header_raw.signature_1 != KDBX_HEADER_SIGNATURE_1 or header_raw.signature_2 != KDBX_HEADER_SIGNATURE_2:
            raise KdbxFileSignatureError()

        if (header_raw.format_version != KDBX_HEADER_FORMAT_VERSION_4) and (header_raw.format_version != KDBX_HEADER_FORMAT_VERSION_4_1):
            raise KdbxFormatVersionError()

        # Parse header fields
        while True:
            header_field_raw = HeaderFieldRaw(fd)

            if header_field_raw.id == KDBX_HEADER_FIELD_ID_EOH:
                # Break at end of header
                break
            elif header_field_raw.id == KDBX_HEADER_FIELD_ID_ENCRYPTION_ALGORITHM:
                self._enc_algo = bytes(header_field_raw.data)
            elif header_field_raw.id == KDBX_HEADER_FIELD_ID_COMPRESSION_ALGORITHM:
                self._comp_algo = unpack_uint32(header_field_raw.data)
            elif header_field_raw.id == KDBX_HEADER_FIELD_ID_MASTER_SALT:
                self._master_salt = bytes(header_field_raw.data)
            elif header_field_raw.id == KDBX_HEADER_FIELD_ID_IV_NONCE:
                self._iv_nonce = bytes(header_field_raw.data)
            elif header_field_raw.id == KDBX_HEADER_FIELD_ID_KDF_PARAMS:
                tmp = io.BytesIO(header_field_raw.data)
                _ = VariantDictHeader(tmp)
                while tmp.tell() < len(header_field_raw.data) - 1:              # Exlude trailing NUL byte
                    vd_field_top = VariantDictFieldTop(tmp)
                    vd_field_bot = VariantDictFieldBottom(tmp)
                    if bytes(vd_field_top.U) == KDBX_VARDICT_KDF_UUID:
                        self._kdf_uuid = bytes(vd_field_bot.V)
                    elif bytes(vd_field_top.U) == KDBX_VARDICT_KDF_S:
                        self._kdf_s = bytes(vd_field_bot.V)
                    elif bytes(vd_field_top.U) == KDBX_VARDICT_KDF_R:
                        self._kdf_r = unpack_uint64(vd_field_bot.V)
                    elif bytes(vd_field_top.U) == KDBX_VARDICT_KDF_V:
                        self._kdf_v = unpack_uint32(vd_field_bot.V)
                    elif bytes(vd_field_top.U) == KDBX_VARDICT_KDF_I:
                        self._kdf_i = unpack_uint64(vd_field_bot.V)
                    elif bytes(vd_field_top.U) == KDBX_VARDICT_KDF_M:
                        self._kdf_m = unpack_uint64(vd_field_bot.V)
                    elif bytes(vd_field_top.U) == KDBX_VARDICT_KDF_P:
                        self._kdf_p = unpack_uint32(vd_field_bot.V)
                    else:
                        raise KdbxParseError('Unknown variant dictionary field')
                _ = VariantDictFooter(tmp)
            else:
                raise KdbxParseError('Unknown header field')

        # Reread header to get raw data for HMAC calulcation
        pos = fd.tell()
        fd.seek(0)
        self._header_data_raw = fd.read(pos)
        fd.seek(pos)

        # Read reference values for Hash/HMAC
        self._hash_ref = fd.read(256 // 8)
        self._hmac_ref = fd.read(256 // 8)

    def _kdbx_calculate_keys(self, password, keyfile_data=None, keyprovider_data=None, dpapi_data=None):
        R_password = hashlib.sha256(password.encode('utf8')).digest()
        R_keyfile = keyfile_data if keyfile_data is not None else bytes()
        R_keyprovider = keyprovider_data if keyprovider_data is not None else bytes()
        R_dpapi = dpapi_data if dpapi_data is not None else bytes()
        R = hashlib.sha256(R_password + R_keyfile + R_keyprovider + R_dpapi).digest()

        if self._kdf_uuid == KDBX_KDF_ALGORITHM_AES:
            # Sources:
            #  - https://github.com/Evidlo/examples/blob/master/python/kdbx4_decrypt.py
            #  - https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ecb-mode
            cipher = AES.new(self._kdf_s, AES.MODE_ECB)
            T = R
            for _ in range(0, self._kdf_r):
                T = cipher.encrypt(T)
            T = hashlib.sha256(T).digest()
        elif self._kdf_uuid == KDBX_KDF_ALGORITHM_ARGON2D:
            T = argon2.PasswordHasher(time_cost=self._kdf_i, memory_cost=self._kdf_m//1024, parallelism=self._kdf_p, hash_len=32, type=argon2.low_level.Type.D)
            T = T.hash(R, salt=self._kdf_s)
            T = T.split("$")[-1]
            T = base64.b64decode(T + '=' * ((3 - len(T) % 4) + 1))
        elif self._kdf_uuid == KDBX_KDF_ALGORITHM_ARGON2ID:
            ph = argon2.PasswordHasher(time_cost=self._kdf_i, memory_cost=self._kdf_m//1024, parallelism=self._kdf_p, hash_len=32, type=argon2.low_level.Type.ID)
            T = ph.hash(R, salt=self._kdf_s)
            T = T.split("$")[-1]
            T = base64.b64decode(T + '=' * ((3 - len(T) % 4) + 1))
        else:
            raise KdbxUnknownEncryptionAlgorithmError()

        self._encryption_key = hashlib.sha256(self._master_salt + T).digest()
        self._hmac_key_fn = lambda block_id: hashlib.sha512(pack_uint64(block_id) + hashlib.sha512(self._master_salt + T + bytes([0x01])).digest()).digest()

    def _kdbx_check_header_integrity(self):
        hash_act = hashlib.sha256(self._header_data_raw).digest()
        hmac_act = hmac.new(self._hmac_key_fn(0xffffffffffffffff), self._header_data_raw, 'sha256').digest()

        if hash_act != self._hash_ref:
            raise KdbxHeaderIntegrityError('Header Hash invalid')

        if hmac_act != self._hmac_ref:
            raise KdbxHeaderIntegrityError('Header HMAC invalid')

    def _kdbx_read_block_data(self, fd):
        self.data = bytes()
        block_idx = 0
        while True:
            block_data = BlockData(fd)

            hmac_data = pack_uint64(block_idx) + pack_uint32(block_data.s) + bytes(block_data.data)
            block_hmac_act = hmac.new(self._hmac_key_fn(block_idx), hmac_data, 'sha256').digest()
            if block_hmac_act != bytes(block_data.hmac):
                raise KdbxDataIntegrityError()
            self.data += bytes(block_data.data)

            # Break on trailing zero length block
            if block_data.s == 0:
                break

            block_idx += 1

    def _kdbx_decrypt_data(self):
        if self._enc_algo == KDBX_ENCRYPTION_ALGORITHM_AES256:
            self.data = AES.new(self._encryption_key, AES.MODE_CBC, iv=self._iv_nonce).decrypt(self.data)
        elif self._enc_algo == KDBX_ENCRYPTION_ALGORITHM_CHACHA20:
            self.data = ChaCha20.new(key=self._encryption_key, nonce=self._iv_nonce).decrypt(self.data)
        elif self._enc_algo == KDBX_ENCRYPTION_ALGORITHM_TWOFISH:
            raise KdbxUnsupportedEncryptionAlgorithmError()
        else:
            raise KdbxUnknownEncryptionAlgorithmError()

    def _kdbx_decompress_data(self):
        if self._comp_algo == KDBX_COMPRESSION_ALGORITHM_NO:
            pass
        elif self._comp_algo == KDBX_COMPRESSION_ALGORITHM_GZIP:
            self.data = zlib.decompress(self.data, wbits=31)
        else:
            raise KdbxUnknownCompressionAlgorithmError()

    def _kdbx_parse_inner_header(self):
        data_stream = io.BytesIO(self.data)
        self.bin_data = []
        while inner_header_field := InnerHeaderField(data_stream):
            if inner_header_field.t == KDBX_INNER_HEADER_FIELD_ID_EOH:
                break
            elif inner_header_field.t == KDBX_INNER_HEADER_FIELD_ID_ENCRYPTION_ALGORITHM:
                inner_header_enc_algo = unpack_uint32(inner_header_field.V)
            elif inner_header_field.t == KDBX_INNER_HEADER_FIELD_ID_ENCRYPTION_KEY:
                inner_header_enc_key = inner_header_field.V
            elif inner_header_field.t == KDBX_INNER_HEADER_FIELD_ID_BINARY_CONTENT:
                # NOTE: Binary content should be "protected in the process memory" if flags 0x01 is set. I have no idea what this means...
                binary_flags = inner_header_field.V[0]
                self.bin_data.append(inner_header_field.V[1:])
            else:
                raise KdbxUnknownInnerHeaderfieldError()

        if inner_header_enc_algo == KDBX_INNER_HEADER_ENCRYPTION_ALGORITHM_SALSA20:
            inner_header_enc_key = hashlib.sha256(inner_header_enc_key).digest()
            inner_header_enc_nonce = KDBX_INNER_HEADER_ENCRYPTION_SALSA20_NONCE
            self._inner_header_enc_obj = Salsa20.new(key=inner_header_enc_key, nonce=inner_header_enc_nonce)
        elif inner_header_enc_algo == KDBX_INNER_HEADER_ENCRYPTION_ALGORITHM_CHACHA20:
            H = hashlib.sha512(inner_header_enc_key).digest()
            inner_header_enc_key = H[:32]
            inner_header_enc_nonce = H[32:44]
            self._inner_header_enc_obj = ChaCha20.new(key=inner_header_enc_key, nonce=inner_header_enc_nonce)
        else:
            raise KdbxUnknownEncryptionAlgorithmError()

        self.data = data_stream.read()
        self.data = self.data.decode('utf8')

    def _kdbx_parse_xml(self):
        self.data = ET.fromstring(self.data)

    def _kdbx_decrypt_process_memory_protection(self):
        for element in self.data.iter():
            if ('Protected' in element.attrib) and (element.attrib['Protected'] == 'True') and (element.text is not None):
                element.text = self._inner_header_enc_obj.decrypt(base64.b64decode(element.text)).decode('utf8')
                element.attrib['Protected'] = 'False'

    def _xparse_get_dbname(self):
        return self.data.find('.//DatabaseName').text

    def _xparse_get_entries(self):
        entries = []
        for entry in self.data.findall('.//Entry'):
            title = entry.findall('./String/Key[.="Title"]../Value')[0].text
            username = entry.findall('./String/Key[.="UserName"]../Value')[0].text
            password = entry.findall('./String/Key[.="Password"]../Value')[0].text
            binaries = {}
            for binary in entry.findall('./Binary'):
                bin_key = binary.find('Key').text
                bin_value = bytes(kdbx_file.bin_data[int(binary.find('Value').attrib['Ref'])])
                binaries[bin_key] = bin_value
            entries.append({'title': title, 'username': username, 'password': password, 'binaries': binaries})
        return entries


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='kdbx-lite', description='Minimal tool to parse and print KeePassXC .kdbx files. ATTENTION: This tool does not care about security!!! DO NOT USE THIS TOOL UNLESS YOU UNDERSTAND THIS!!!')
    parser.add_argument('filename')
    parser.add_argument('password')
    args = parser.parse_args()
    kdbx_file = KdbxFile(args.filename, args.password)
    print(kdbx_file)
