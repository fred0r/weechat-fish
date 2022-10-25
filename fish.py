"""
A WeeChat FiSH IRC Encryption Python 3 Script
Copyright (C) 2022  orkim <d.orkim@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

TODO - Fix TODOs. :D

TODO - Look into using sec.* for storage?
"""

import argparse
import base64
import hashlib
import os
import re
import struct
from dataclasses import dataclass
from operator import attrgetter

from Crypto.Cipher import Blowfish
from Crypto.Util.strxor import strxor

SCRIPT_NAME = 'fish'
SCRIPT_AUTHOR = 'orkim <d.orkim@gmail.com>'
SCRIPT_VERSION = '0.1'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = 'FiSH for WeeChat'
CONFIG_FILE_NAME = SCRIPT_NAME

import_ok = True

try:
    import weechat
except ImportError:
    print('This script must be run under WeeChat.')
    print('Get WeeChat now at: https://weechat.org/')
    import_ok = False

try:
    import Crypto.Cipher.Blowfish
except ImportError:
    print(f'pycryptodome must be installed to use {SCRIPT_NAME}.py')
    import_ok = False

records = []


def int_to_bytes(n):
    """
    Convert an integer to bytes stored in big-endian format.
    """
    if n == 0:
        return bytes(1)
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes(b)


def bytes_to_int(b):
    """
    Convert bytes stored in big-endian format to an integer.
    """
    n = 0
    for p in b:
        n <<= 8
        n += p
    return n


def pad_to(msg, multiple):
    """
    Pads msg with 0s until it's length is divisible by `multiple`.
    """
    return msg + bytes(-len(msg) % multiple)


def cbc_encrypt(func, data, blocksize):
    """
    Uses func to encrypt data in CBC mode using a randomly generated IV.
    The IV is prefixed to the ciphertext.

    args:
        func:       a function that encrypts data in ECB mode
        data:       plaintext
        blocksize:  block size of the cipher
    """
    assert len(data) % blocksize == 0
    iv = os.urandom(blocksize)
    assert len(iv) == blocksize
    ciphertext = iv
    for block_index in range(len(data) // blocksize):
        xored = strxor(data[:blocksize], iv)
        enc = func(xored)
        ciphertext += enc
        iv = enc
        data = data[blocksize:]
    assert len(ciphertext) % blocksize == 0
    return ciphertext


def cbc_decrypt(func, data, blocksize):
    assert len(data) % blocksize == 0
    iv = data[0:blocksize]
    data = data[blocksize:]
    plaintext = b''
    for block_index in range(len(data) // blocksize):
        temp = func(data[0:blocksize])
        temp2 = strxor(temp, iv)
        plaintext += temp2
        iv = data[0:blocksize]
        data = data[blocksize:]
    assert len(plaintext) % blocksize == 0
    return plaintext


class DH1080:
    """Diffie-Hellman Key Exchange Class

    Initiating a request:
        dh.send_request() -> dh.receive_any()
        key will now be available via dh.get_secret()

    Replying to an initiated request:
        dh.receive_any() -> dh.send_response()
        key will now be available via dh.get_secret()
    """
    g = 2
    # noinspection SpellCheckingInspection
    p = int(
        'FBE1022E23D213E8ACFA9AE8B9DFAD'
        'A3EA6B7AC7A7B7E95AB5EB2DF85892'
        '1FEADE95E6AC7BE7DE6ADBAB8A783E'
        '7AF7A7FA6A2B7BEB1E72EAE2B72F9F'
        'A2BFB2A2EFBEFAC868BADB3E828FA8'
        'BADFADA3E4CC1BE7E8AFE85E9698A7'
        '83EB68FA07A77AB6AD7BEB618ACF9C'
        'A2897EB28A6189EFA07AB99A8A7FA9'
        'AE299EFA7BA66DEAFEFBEFBF0B7D8B',
        16
    )
    q = (p - 1) // 2

    def __init__(self):
        self.public = 0
        self.private = 0
        self.secret = 0
        # 0: private key initialized, 1: sent request, 2: received request, 3: finished
        self.stage = 0
        self.cbc = None
        g, p, q = self.g, self.p, self.q
        bits = 1080
        while True:
            self.private = bytes_to_int(os.urandom(bits // 8))
            self.public = pow(g, self.private, p)
            if self.validate_public_key(self.public) and self.validate_public_key_strict(self.public):
                break

    @staticmethod
    def b64encode(s):
        """
        Non-standard base64 encode, without padding characters and encodes at least one additional zero bit.
        """
        res = base64.b64encode(s)
        if res.endswith(b'='):
            res = res.rstrip(b'=')
        else:
            res += b'A'
        return res

    @staticmethod
    def b64decode(s):
        # remove padding A
        if len(s) % 4 == 1:
            s = s[:-1]
        # add padding characters
        s += b'=' * ((-len(s)) % 4)
        return base64.b64decode(s)

    def validate_public_key(self, public_key):
        return 1 < public_key < self.p

    def validate_public_key_strict(self, public_key):
        """
        See RFC 2631 section 2.1.5.
        """
        return pow(public_key, self.q, self.p) == 1

    @classmethod
    def pack(cls, cmd, key, cbc):
        res = '{} {}'.format(cmd, cls.b64encode(int_to_bytes(key)).decode())
        if cbc:
            res += ' CBC'
        return res

    @classmethod
    def unpack(cls, msg):
        words = msg.split()
        if len(words) not in (2, 3):
            raise ValueError('msg')
        cbc = False
        if len(words) == 3:
            if words[-1] == 'CBC':
                cbc = True
        cmd = words[0]
        if cmd not in ('DH1080_INIT', 'DH1080_FINISH'):
            raise ValueError('msg')
        key = bytes_to_int(cls.b64decode(words[1].encode()))
        return cmd, key, cbc

    def send_request(self, cbc):
        if self.stage != 0:
            raise ValueError('stage')
        self.cbc = cbc
        self.stage = 1
        return self.pack('DH1080_INIT', self.public, cbc)

    def send_response(self):
        if self.stage != 2:
            raise ValueError('stage')
        self.stage = 3
        return self.pack('DH1080_FINISH', self.public, self.cbc)

    def receive_any(self, msg):
        cmd, public_key, cbc = self.unpack(msg)
        if cmd == 'DH1080_INIT':
            if self.stage != 0:
                raise ValueError('stage')
            self.cbc = cbc
        elif cmd == 'DH1080_FINISH':
            if self.stage != 1:
                raise ValueError('stage')
            if cbc != self.cbc:
                print('Warning: cbc request received a non-cbc response')
                self.cbc = False
        if not self.validate_public_key(public_key):
            raise ValueError('invalid public key')
        if not self.validate_public_key_strict(public_key):
            print('Warning: key does not conform to RFC 2631.')
        self.secret = pow(public_key, self.private, self.p)
        # advance stage if there are no errors
        if cmd == 'DH1080_INIT':
            self.stage = 2
        elif cmd == 'DH1080_FINISH':
            self.stage = 3

    def get_secret(self):
        if self.secret == 0:
            raise ValueError
        return self.b64encode(hashlib.sha256(int_to_bytes(self.secret)).digest())


class BlowCryptBase:
    """Base Blowfish Class

    """
    send_prefix = ''
    receive_prefixes = []

    def __init__(self, key=None):
        if not 8 <= len(key) <= 56:
            raise ValueError('8 <= len(key) <= 56')
        self.blowfish = Blowfish.new(key.encode(), Blowfish.MODE_ECB)

    @classmethod
    def b64encode(cls, s):
        raise NotImplementedError

    @classmethod
    def b64decode(cls, s, partial=False):
        raise NotImplementedError

    def pack(self, msg):
        """Encrypt, pad, and encode a message to be sent via IRC.

        """
        return '{}{}'.format(self.send_prefix, self.b64encode(self.encrypt(pad_to(msg.encode(), 8))).decode())

    def unpack(self, msg, partial=False):
        """Decode, and decrypt a message received via IRC.

        """
        try:
            prefix = next(prefix for prefix in self.receive_prefixes if msg.startswith(prefix))
        except StopIteration:
            raise ValueError
        body = msg[len(prefix):]
        return self.decrypt(self.b64decode(body.encode(), partial)).strip(b'\x00').decode('utf-8', 'ignore')

    def encrypt(self, msg):
        raise NotImplementedError

    def decrypt(self, msg):
        raise NotImplementedError


class BlowCrypt(BlowCryptBase):
    """Blowfish EBC Class

    """
    send_prefix = '+OK '
    # noinspection SpellCheckingInspection
    receive_prefixes = ['+OK ', 'mcps ']
    # noinspection SpellCheckingInspection
    b64_alphabet = b'./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    @classmethod
    def b64encode(cls, s):
        """
        Non-standard base64 encode with various bit & endian reversals.
        """
        res = bytearray()
        if len(s) % 8 != 0:
            raise ValueError
        for i in range(0, len(s), 8):
            left, right = struct.unpack('>LL', s[i:i + 8])
            for j in range(6):
                res.append(cls.b64_alphabet[right & 0x3f])
                right >>= 6
            for j in range(6):
                res.append(cls.b64_alphabet[left & 0x3f])
                left >>= 6
        return bytes(res)

    @classmethod
    def b64decode(cls, s, partial=False):
        """
        Non-standard base64 decode with various bit & endian reversals.
        """
        res = bytearray()
        if not partial and len(s) % 12 != 0:
            raise ValueError
        try:
            for i in range(0, len(s) // 12 * 12, 12):
                left, right = 0, 0
                for j, p in enumerate(s[i:i + 6]):
                    right |= cls.b64_alphabet.index(p) << (j * 6)
                for j, p in enumerate(s[i + 6:i + 12]):
                    left |= cls.b64_alphabet.index(p) << (j * 6)
                res.extend(struct.pack('>LL', left, right))
        except ValueError:
            if not partial:
                raise
        return bytes(res)

    def encrypt(self, data):
        return self.blowfish.encrypt(data)

    def decrypt(self, data):
        return self.blowfish.decrypt(data)


class BlowCryptCBC(BlowCryptBase):
    """Blowfish CBC Class

    """
    send_prefix = '+OK *'
    # noinspection SpellCheckingInspection
    receive_prefixes = ['+OK *', 'mcps *']

    @classmethod
    def b64encode(cls, s):
        if len(s) % 8 != 0:
            raise ValueError
        return base64.b64encode(s)

    @classmethod
    def b64decode(cls, s, partial=False):
        return base64.b64decode(s, validate=True)

    def encrypt(self, data):
        return cbc_encrypt(self.blowfish.encrypt, data, 8)

    def decrypt(self, data):
        return cbc_decrypt(self.blowfish.decrypt, data, 8)


def find_msg_cls(msg):
    """Determine the appropriate class based on message prefix.

    Returns an object of BlowCrypt or BlowCryptCBC that can be used to decrypt the message based on the format of the
    supplied message.

    Raises a ValueError if no match is found.
    """
    # BlowCryptCBC has precedence since it's prefixes contain the prefixes of BlowCrypt
    for cls in (BlowCryptCBC, BlowCrypt):
        if any(msg.startswith(prefix) for prefix in cls.receive_prefixes):
            return cls
    raise ValueError('msg')


@dataclass
class Record:
    """Dataclass to hold keys/DH objects.

    TODO - expire DH object
     The DH object could be expired after a certain amount of time (maximum IRC lag timeout) and cleaned up.
     Currently, they will stick around until script restart if they don't complete.
    """
    network: str
    target: str
    dh: DH1080 = None
    key: str = None
    cbc: bool = False


class ArgumentParserException(Exception):
    """An exception for our derived class.

    """
    pass


class ArgumentParser(argparse.ArgumentParser):
    """Derived ArgumentParser Class.

    We are going to override any of the 'exit' or 'print' functions as we don't want to print to stdout/stderr.
    """

    def print_usage(self, file=None):
        raise ArgumentParserException

    def print_help(self, file=None):
        raise ArgumentParserException

    def error(self, message):
        raise ArgumentParserException

    def exit(self, status=0, message=None):
        raise ArgumentParserException


def fish_modifier_in2_notice_cb(data, modifier, server_name, string):
    """Callback for incoming notices from IRC server.

    """
    match = re.match(
        r'^((?:@[^ ]* )?:(.*?)!.*? NOTICE (.*?) :)((DH1080_INIT |DH1080_FINISH )?.*)$',
        string)
    # match.group(0): message
    # match.group(1): msg without payload
    # match.group(2): source
    # match.group(3): target
    # match.group(4): msg
    # match.group(5): "DH1080_INIT "|"DH1080_FINISH "

    # no match. just return same string for processing
    if match is None:
        return string

    source_str = match.group(2)
    msg_str = match.group(4)
    start_str = match.group(5)

    buffer = weechat.info_get('irc_buffer', f'{server_name},{source_str}')

    if start_str == 'DH1080_INIT ':
        key_exchange = weechat.config_string(weechat.config_get('fish.options.key_exchange'))
        if key_exchange == "off":
            # we're not going to reply, just pass back for display
            return string

        # respond
        dh = DH1080()
        dh.receive_any(msg_str)
        msg = dh.send_response()
        weechat.command(buffer, f'/mute notice -server {server_name} {source_str} {msg}')

        # store new record
        record = find_or_create_record(server_name, source_str)
        record.key = dh.get_secret().decode()

        # handle displaying result
        if dh.cbc:
            fish_type_str = '[fish-cbc exchange]'
            record.cbc = True
        else:
            fish_type_str = '[fish-ebc exchange]'
            record.cbc = False

        # print out two messages
        msg1 = f'{SCRIPT_NAME}: {fish_type_str} received key exchange request from {record.target}@{record.network}'
        msg2 = f'{SCRIPT_NAME}: {fish_type_str} successfully set key to "{record.key}"'
        weechat.prnt(buffer, msg1)
        weechat.prnt(buffer, msg2)

        # eat the notice
        return ''

    if start_str == 'DH1080_FINISH ':

        # search our records
        record = find_record(server_name, source_str)
        if record:
            # make sure we're in an exchange
            if record.dh:
                # finish exchange
                record.dh.receive_any(msg_str)
                record.key = record.dh.get_secret().decode()

                # handle displaying result
                if record.dh.cbc:
                    fish_type_str = '[fish-cbc exchange]'
                else:
                    fish_type_str = '[fish-ebc exchange]'
                weechat.prnt(buffer, f'{SCRIPT_NAME}: {fish_type_str} successfully set key to "{record.key}"')

                # clean up
                del record.dh

                # eat the notice
                return ''

            # got a finish, but we are not in an exchange
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Warning: Got DH1080_FINISH without a start')

        else:
            # got a finish, but we have no record
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Warning: Got DH1080_FINISH without a record')

        # just return same string for display
        return string

    # just return same string for processing
    return string


def fish_modifier_out_privmsg_cb(data, modifier, server_name, string):
    """Callback for outgoing PRIVMSGS to IRC server.

    """
    if type(string) is bytes:
        weechat.prnt('', f'{SCRIPT_NAME}: failed check #1')
        return string

    match = re.match(r"^(PRIVMSG (.*?) :)(.*)$", string)
    # match.group(0): message
    # match.group(1): msg prefix (without payload)
    # match.group(2): target
    # match.group(3): msg

    if match is None:
        weechat.prnt('', f'{SCRIPT_NAME}: failed check #3')
        return string

    msg_prefix_str = match.group(1)
    target_str = match.group(2)
    msg_str = match.group(3)

    record = find_record(server_name, target_str)
    if record is None:
        return string

    try:
        if record.cbc:
            msg = BlowCryptCBC(record.key).pack(msg_str)
        else:
            msg = BlowCrypt(record.key).pack(msg_str)
    except ValueError:
        weechat.prnt('', f'{SCRIPT_NAME}: failed to encrypt outgoing privmsg. not sent.')
        return ''

    return f'{msg_prefix_str}{msg}'


def fish_modifier_out_notice_cb(data, modifier, server_name, string):
    """Callback for outgoing NOTICES to IRC server.

    """
    if type(string) is bytes:
        weechat.prnt('', f'{SCRIPT_NAME}: failed check #2')
        return string

    # check for outgoing DH1080
    match = re.match(
        r'^NOTICE .*? :(?:DH1080_INIT |DH1080_FINISH ).*$',
        string)
    # match.group(0): message
    # match.group(1): msg without payload
    # match.group(2): source
    # match.group(3): target
    # match.group(4): msg
    # match.group(5): "DH1080_INIT "|"DH1080_FINISH "
    if match is not None:
        # do not encrypt outgoing DH1080 exchanges even if we have a key
        return string

    match = re.match(r"^(NOTICE (.*?) :)(.*)$", string)
    # match.group(0): message
    # match.group(1): msg prefix (without payload)
    # match.group(2): target
    # match.group(3): notice
    if match is None:
        weechat.prnt('', f'{SCRIPT_NAME}: failed check #4')
        return string

    msg_prefix_str = match.group(1)
    target_str = match.group(2)
    notice_str = match.group(3)

    record = find_record(server_name, target_str)
    if record is None:
        return string

    try:
        if record.cbc:
            notice = BlowCryptCBC(record.key).pack(notice_str)
        else:
            notice = BlowCrypt(record.key).pack(notice_str)
    except ValueError:
        weechat.prnt('', f'{SCRIPT_NAME}: failed to encrypt outgoing notice. not sent.')
        return ''

    return f'{msg_prefix_str}{notice}'


def fish_modifier_out_topic_cb(data, modifier, server_name, string):
    """Callback for outgoing TOPICS to IRC server.

    """
    if type(string) is bytes:
        weechat.prnt('', f'{SCRIPT_NAME}: failed check #5')
        return string

    match = re.match(r"^(TOPIC (.*?) :)(.*)$", string)
    # match.group(0): message
    # match.group(1): msg prefix (without payload)
    # match.group(2): target
    # match.group(3): topic
    if match is None:
        weechat.prnt('', f'{SCRIPT_NAME}: failed check #6')
        return string

    if not match.group(3):
        weechat.prnt('', f'{SCRIPT_NAME}: failed check #7')
        return string

    msg_prefix_str = match.group(1)
    target_str = match.group(2)
    topic_str = match.group(3)

    record = find_record(server_name, target_str)
    if record is None:
        return string

    try:
        if record.cbc:
            topic = BlowCryptCBC(record.key).pack(topic_str)
        else:
            topic = BlowCrypt(record.key).pack(topic_str)
    except ValueError:
        weechat.prnt('', f'{SCRIPT_NAME}: failed to encrypt outgoing topic command. not sent.')
        return ''

    return f'{msg_prefix_str}{topic}'


def fish_hook_line_cb(data: str, line: dict[str, str]) -> dict[str, str]:
    """Call back for displaying a line in a buffer.

    Decoding and decorating is done here.
    """
    buffer = line['buffer']
    tags = line['tags']
    message = line['message']

    server_name = weechat.buffer_get_string(buffer, 'localvar_server')
    buffer_type = weechat.buffer_get_string(buffer, 'localvar_type')

    if not server_name or not buffer_type:
        return dict()

    target_str = None
    msg_str = None

    # handle OUTGOING text decoration (special case: return from within block)
    if 'self_msg' in tags:
        if buffer_type in ('channel', 'private') and 'irc_privmsg' in tags:
            # decorate outgoing privmsg on channels/buffers
            target_str = weechat.buffer_get_string(buffer, 'localvar_channel')

        elif buffer_type == 'server' and 'irc_privmsg' in tags:
            # decorate outgoing privmsg on server buffers
            clean_msg = weechat.string_remove_color(message, '')
            match = re.match(
                r'^MSG\((.*?)\): (.*)$',
                clean_msg
            )
            # match.group(0): message
            # match.group(1): destination
            # match.group(2): message
            if match:
                target_str = match.group(1)

        else:
            # decorate outgoing notices (server, channel, private query windows)
            # we just have to try outgoing notices on a server buffer, no tags to find
            clean_msg = weechat.string_remove_color(message, '')
            match = re.match(
                r'^Notice -> (.*?): (.*)$',
                clean_msg
            )
            # match.group(0): message
            # match.group(1): destination
            # match.group(2): notice message
            if match:
                target_str = match.group(1)

        if target_str is not None:
            record = find_record(server_name, target_str)
            if record and record.key:
                # TODO - This seems wrong, investigate this
                # fixed_prefix = line['prefix'].strip()
                fixed_prefix = line['prefix'].strip().replace(" ", "")

                # DECORATE THE OUTGOING MESSAGE
                position = weechat.config_string(weechat.config_get("fish.look.mark_position"))
                if record.cbc:
                    marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_cbc"))
                    marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_cbc"))
                else:
                    marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_ebc"))
                    marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_ebc"))

                if position == "begin":
                    prefix = f'{weechat.color(marker_color)}{marker_char}{fixed_prefix}'
                elif position == "end":
                    prefix = f'{fixed_prefix}{weechat.color(marker_color)}{marker_char}'
                else:
                    return {
                        'tags': f'{tags},encrypted'
                    }

                return {
                    'prefix': f'{prefix}',
                    'tags': f'{tags},encrypted',
                }

        # failed to match record, not decorating our outgoing message
        return dict()

    # handle INCOMING topic on join (special case: return from within block)
    elif 'irc_332' in tags:
        # handles 'on join' and query with '/topic'
        match = re.match(
            r'^Topic for (.*) is "(.*)"$',
            message
        )

        if match:
            # TODO - This seems fragile, investigate this
            # first 3 bytes, and last byte are control codes
            target_str = match.group(1)[3:-1]
            # first 4 bytes, and last byte are control codes
            msg_str = match.group(2)[4:-1]

            # look up if we have a record
            record = find_record(server_name, target_str)
            if record:
                if record.key is not None:
                    # make sure this is encrypted (notice or privmsg)
                    if msg_str.startswith('+OK ') or msg_str.startswith('mcps '):
                        if record.key is not None:
                            cls = find_msg_cls(msg_str)
                            msg_str = cls(record.key).unpack(msg_str)
                            if '\x00' in msg_str:
                                weechat.prnt(buffer, f'{SCRIPT_NAME}: found null byte in decoded message. bad key?')
                            else:
                                irc_color_decoded = weechat.hook_modifier_exec('irc_color_decode', '1', msg_str)

                            # TODO - This seems fragile, investigate this
                            # add back in control codes
                            target_str = match.group(1)
                            msg_str = match.group(2)[:4] + irc_color_decoded + match.group(2)[-1:]

                            position = weechat.config_string(weechat.config_get("fish.look.mark_position"))
                            if record.cbc:
                                marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_cbc"))
                                marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_cbc"))
                            else:
                                marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_ebc"))
                                marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_ebc"))

                            if position == "begin":
                                prefix = f'{weechat.color(marker_color)}{marker_char}{line["prefix"]}'
                            elif position == "end":
                                prefix = f'{line["prefix"]}{weechat.color(marker_color)}{marker_char}'
                            else:
                                return {
                                    'tags': f'{tags},encrypted',
                                    'message': f'Topic for {target_str} is "{msg_str}"',
                                }

                            return {
                                'prefix': f'{prefix}',
                                'tags': f'{tags},encrypted',
                                'message': f'Topic for {target_str} is "{msg_str}"',
                            }
                else:
                    weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: Got encrypted data, but no key to decrypt.')

        # failed to match record, not decorating our message
        return dict()

    # handle INCOMING topic changes (special case: return from within block)
    elif 'irc_topic' in tags:
        # TODO: handle '/topic -delete' when unsetting the topic
        #  sting: {nick} has unset topic for {channel} (old topic: "{old_topic}}")
        match = re.match(
            r'^(.*) has changed topic for (.*) from "(.*)" to "(.*)"$',
            message
        )

        if match:
            nickname_str = match.group(1)
            # TODO - This seems fragile, investigate this
            # first 3 bytes, and last byte are control codes
            target_str = match.group(2)[3:-1]
            # first 4 bytes, and last byte are control codes
            old_topic_str = match.group(3)[4:-1]
            new_topic_str = match.group(4)[4:-1]

            # look up if we have a record
            record = find_record(server_name, target_str)
            if record:
                if record.key is not None:
                    decoded = False

                    # make sure this is encrypted (notice or privmsg)
                    if old_topic_str.startswith('+OK ') or old_topic_str.startswith('mcps '):
                        if record.key is not None:
                            cls = find_msg_cls(old_topic_str)
                            old_topic = cls(record.key).unpack(old_topic_str)
                            if '\x00' in old_topic:
                                weechat.prnt(buffer, f'{SCRIPT_NAME}: found null byte in decoded topic. bad key?')
                            else:
                                old_topic_str = weechat.hook_modifier_exec('irc_color_decode', '1', old_topic)
                            decoded = True
                    # TODO - This seems fragile, investigate this
                    # add back in control codes
                    old_topic_str = match.group(3)[:4] + old_topic_str + match.group(3)[-1:]

                    if new_topic_str.startswith('+OK ') or new_topic_str.startswith('mcps '):
                        if record.key is not None:
                            cls = find_msg_cls(new_topic_str)
                            new_topic = cls(record.key).unpack(new_topic_str)
                            if '\x00' in new_topic:
                                weechat.prnt(buffer, f'{SCRIPT_NAME}: found null byte in decoded topic. bad key?')
                            else:
                                new_topic_str = weechat.hook_modifier_exec('irc_color_decode', '1', new_topic)
                            decoded = True
                    # TODO - This seems fragile, investigate this
                    # add back in control codes
                    new_topic_str = match.group(4)[:4] + new_topic_str + match.group(4)[-1:]

                    # TODO - This seems fragile, investigate this
                    # add back in control codes
                    target_str = match.group(2)

                    if decoded:
                        position = weechat.config_string(weechat.config_get("fish.look.mark_position"))
                        if record.cbc:
                            marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_cbc"))
                            marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_cbc"))
                        else:
                            marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_ebc"))
                            marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_ebc"))

                        if position == "begin":
                            prefix = f'{weechat.color(marker_color)}{marker_char}{line["prefix"]}'
                        elif position == "end":
                            prefix = f'{line["prefix"]}{weechat.color(marker_color)}{marker_char}'
                        else:
                            return {
                                'tags': f'{tags},encrypted',
                                'message': f'{nickname_str} has changed topic for {target_str} from '
                                           f'"{old_topic_str}" to "{new_topic_str}"',
                            }

                        return {
                            'prefix': f'{prefix}',
                            'tags': f'{tags},encrypted',
                            'message': f'{nickname_str} has changed topic for {target_str} from '
                                       f'"{old_topic_str}" to "{new_topic_str}"',
                        }
                else:
                    weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: Got encrypted data, but no key to decrypt.')

        # failed to match record, not decorating our message
        return dict()

    # handle INCOMING encrypted notices (display on server buffer, channel buffer, or in query window)
    # note: dh1080 exchange is handled at a lower level
    elif 'irc_notice' in tags:

        # parse source from tags
        source_str = ''
        tags_split = tags.split(',')
        for tag in tags_split:
            if tag.startswith('nick_'):
                source_str = tag[5:]
                break

        # split nick/notice from message
        m_split = message.split(': ', maxsplit=1)
        if len(m_split) < 2:
            return dict()
        notice_message_str = m_split[1]

        # set our target/msg and fall through
        target_str = source_str
        msg_str = notice_message_str

        # look up if we have a record
        record = find_record(server_name, target_str)
        if record:
            # make sure this is encrypted notice
            if msg_str.startswith('+OK ') or msg_str.startswith('mcps '):
                if record.key is not None:
                    cls = find_msg_cls(msg_str)
                    msg_str = cls(record.key).unpack(msg_str)
                    if '\x00' in msg_str:
                        weechat.prnt(buffer, f'{SCRIPT_NAME}: found null byte in decoded notice. bad key?')
                    else:
                        irc_color_decoded = weechat.hook_modifier_exec('irc_color_decode', '1', msg_str)

                    # Put our notice message payload back together.
                    msg_str = f'{m_split[0]} {irc_color_decoded}'

                    # DECORATE THE INCOMING NOTICE
                    position = weechat.config_string(weechat.config_get("fish.look.mark_position"))
                    if record.cbc:
                        marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_cbc"))
                        marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_cbc"))
                    else:
                        marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_ebc"))
                        marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_ebc"))

                    if position == "begin":
                        prefix = f'{weechat.color(marker_color)}{marker_char}{line["prefix"]}'
                    elif position == "end":
                        prefix = f'{line["prefix"]}{weechat.color(marker_color)}{marker_char}'
                    else:
                        return {
                            'tags': f'{tags},encrypted',
                            'message': f'{msg_str}'
                        }

                    return {
                        'prefix': f'{prefix}',
                        'tags': f'{tags},encrypted',
                        'message': f'{msg_str}'
                    }
                else:
                    weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: Got encrypted data, but no key to decrypt.')

        # failed to match record, not decorating our message
        return dict()

    # handle INCOMING channel or private query privmsg
    elif buffer_type in ('channel', 'private') and 'irc_privmsg' in tags:
        # set our target/msg and fall through
        target_str = weechat.buffer_get_string(buffer, 'localvar_channel')
        msg_str = message

        # look up if we have a record
        record = find_record(server_name, target_str)
        if record:
            # make sure this is encrypted privmsg
            if msg_str.startswith('+OK ') or msg_str.startswith('mcps '):
                if record.key is not None:
                    cls = find_msg_cls(msg_str)
                    msg_str = cls(record.key).unpack(msg_str)
                    if '\x00' in msg_str:
                        weechat.prnt(buffer, f'{SCRIPT_NAME}: found null byte in decoded message. bad key?')
                    else:
                        irc_color_decoded = weechat.hook_modifier_exec('irc_color_decode', '1', msg_str)

                    # check for action
                    match = re.match(
                        r'^\x01ACTION (.*)\x01',
                        irc_color_decoded
                    )
                    if match is not None:
                        # TODO - This seems wrong, investigate this
                        # fixed_action_prefix = weechat.prefix("action").strip()
                        fixed_action_prefix = weechat.prefix("action").strip().replace(" ", "")

                        # DECORATE THE INCOMING ACTION
                        position = weechat.config_string(weechat.config_get("fish.look.mark_position"))
                        if record.cbc:
                            marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_cbc"))
                            marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_cbc"))
                        else:
                            marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_ebc"))
                            marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_ebc"))

                        if position == "begin":
                            prefix = f'{weechat.color(marker_color)}{marker_char}{fixed_action_prefix}'
                        elif position == "end":
                            prefix = f'{fixed_action_prefix}{weechat.color(marker_color)}{marker_char}'
                        else:
                            return {
                                'tags': f'{line["tags"]},irc_action,encrypted',
                                'message': f'{line["prefix"]}{weechat.color("reset")} {match.group(1)}',
                            }

                        return {
                            'prefix': f'{prefix}',
                            'tags': f'{line["tags"]},irc_action,encrypted',
                            'message': f'{line["prefix"]}{weechat.color("reset")} {match.group(1)}',
                        }

                    # DECORATE THE INCOMING MESSAGE
                    position = weechat.config_string(weechat.config_get("fish.look.mark_position"))
                    if record.cbc:
                        marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_cbc"))
                        marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_cbc"))
                    else:
                        marker_char = weechat.config_string(weechat.config_get("fish.look.mark_character_ebc"))
                        marker_color = weechat.config_color(weechat.config_get("fish.look.mark_color_ebc"))

                    if position == "begin":
                        prefix = f'{weechat.color(marker_color)}{marker_char}{line["prefix"]}'
                    elif position == "end":
                        prefix = f'{line["prefix"]}{weechat.color(marker_color)}{marker_char}'
                    else:
                        return {
                            'tags': f'{tags},encrypted',
                            'message': f'{irc_color_decoded}'
                        }

                    return {
                        'prefix': f'{prefix}',
                        'tags': f'{tags},encrypted',
                        'message': f'{irc_color_decoded}'
                    }
                else:
                    weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: Got encrypted data, but no key to decrypt.')

        # failed to match record, not decorating our message
        return dict()

    return dict()


def invalid_server(server: str, connected_check: bool):
    """Check a user supplied string for valid IRC server.

    First we check to ensure the IRC server exists, and optionally check if we're connected.

    Return:

    If any check fails, a string with an error message will be returned.

    On success, this function returns False.
    """

    # assume we were passed a good server
    ret = False

    # search our infolist
    infolist = weechat.infolist_get('irc_server', '', server)
    if not infolist:
        return 'Error: infolist_get() call failed.'
    rc = weechat.infolist_next(infolist)
    if rc:
        if connected_check and not weechat.infolist_integer(infolist, 'is_connected'):
            ret = f'Error: You are not currently connected to {server}.'
    else:
        ret = f'Error: No server named "{server}" found.'
    weechat.infolist_free(infolist)

    # return our result
    return ret


def find_record(network_name: str, target_name: str):
    """Find a record.

    Finds a record, if it exists, and returns it. Otherwise, None is returned.
    """
    global records

    # ensure target_name is lowercase
    target_name = target_name.lower()

    # search our records
    for record in records:
        if record.network == network_name and record.target == target_name:
            return record

    # not found
    return None


def find_or_create_record(network_name: str, target_name: str) -> Record:
    """Find or create a record.

    Finds a record, or creates a new record if not found, and returns it.
    """
    global records

    # find existing record
    record = find_record(network_name, target_name)

    # create new if needed
    if record is None:
        # ensure target_name is lowercase
        target_name = target_name.lower()

        # create new record
        record = Record(network_name, target_name)
        records.append(record)

    # return record
    return record


def delete_record(network_name: str, target_name: str) -> None:
    """Delete a record.

    Deletes a record (if found).

    Note: Will delete duplicate records (if they exist).
    """
    global records

    # search our records
    for record in records:
        if record.network == network_name and record.target == target_name:
            records.remove(record)

    # not found
    return


def config_keys_read(data: str, config_file: str, section: str, option_name: str, value: str) -> int:
    # read in the keys
    try:
        option_name_split = option_name.split(',')
        value_split = value.split(',')

        record = find_or_create_record(option_name_split[0], option_name_split[1])
        record.key = value_split[0]
        record.cbc = value_split[1]

        return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED
    except IndexError:
        return weechat.WEECHAT_CONFIG_OPTION_SET_ERROR


def config_keys_write(data: str, config_file: str, section_name: str) -> int:
    # write out the section
    weechat.config_write_line(config_file, "keys", "")

    # write out the keys
    for record in records:
        name = f'{record.network},{record.target}'
        value = f'{record.key},{record.cbc}'
        weechat.config_write_line(config_file, name, value)

    return weechat.WEECHAT_CONFIG_WRITE_OK


def fish_config_init():
    """Configuration file initialization.

    """

    fish_config_file = weechat.config_new(CONFIG_FILE_NAME, 'fish_config_reload_cb', '')
    if not fish_config_file:
        return

    # look
    fish_config_section_look = weechat.config_new_section(fish_config_file,
                                                          'look', 0, 0, '', '', '', '', '', '', '', '', '', '')
    if not fish_config_section_look:
        weechat.config_free(fish_config_file)
        return

    weechat.config_new_option(fish_config_file, fish_config_section_look, 'mark_position',
                              'integer', 'disable or set encryption marker to beginning or end of prefix',
                              'off|begin|end', 0, 2, 'end', 'end', 0, '', '', '', '', '', '')

    weechat.config_new_option(fish_config_file, fish_config_section_look, 'mark_character_ebc',
                              'string', 'marker character for EBC encrypted messages', '', 0, 0,
                              '#', '#', 0, '', '', '', '', '', '')

    weechat.config_new_option(fish_config_file, fish_config_section_look, 'mark_color_ebc',
                              'color', 'marker color for EBC encrypted messages', '', 0, 0,
                              'lightred', 'lightred', 0, '', '', '', '', '', '')

    weechat.config_new_option(fish_config_file, fish_config_section_look, 'mark_character_cbc',
                              'string', 'marker character for CBC encrypted messages', '', 0, 0,
                              '*', '*', 0, '', '', '', '', '', '')

    weechat.config_new_option(fish_config_file, fish_config_section_look, 'mark_color_cbc',
                              'color', 'marker color for CBC encrypted messages', '', 0, 0,
                              'lightgreen', 'lightgreen', 0, '', '', '', '', '', '')

    # options
    fish_config_section_options = weechat.config_new_section(fish_config_file,
                                                             'options', 0, 0, '', '', '', '', '', '', '', '', '', '')

    if not fish_config_section_options:
        weechat.config_free(fish_config_file)
        return

    weechat.config_new_option(fish_config_file, fish_config_section_options, 'key_exchange',
                              'boolean', 'enable/disable replying to DH1080 key exchange requests', '', 0, 0,
                              'on', 'on', 0, '', '', '', '', '', '')

    # keys
    fish_config_section_keys = weechat.config_new_section(fish_config_file,
                                                          'keys', 0, 0,
                                                          'config_keys_read', '',
                                                          'config_keys_write', '',
                                                          '', '', '', '', '', '')
    if not fish_config_section_keys:
        weechat.config_free(fish_config_file)
        return

    # return our config file pointer
    return fish_config_file


def fish_cmd(data, buffer, args):
    """Callback for the /fish command from WeeChat.

    """
    # parse arguments
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('list')

    exchange_cmd = subparsers.add_parser('exchange')
    exchange_cmd.add_argument('--old', '-o', action='store_true')
    exchange_cmd.add_argument('--server', '-s')
    exchange_cmd.add_argument('nick', nargs='?')

    set_cmd = subparsers.add_parser('set')
    set_cmd.add_argument('--old', '-o', action='store_true')
    set_cmd.add_argument('--server', '-s')
    set_cmd.add_argument('--target', '-t')
    set_cmd.add_argument('key')

    remove_cmd = subparsers.add_parser('remove')
    remove_cmd.add_argument('--server', '-s')
    remove_cmd.add_argument('--target', '-t')

    try:
        parsed_args = parser.parse_args(args.split())
    except ArgumentParserException:
        # special case, no SCRIPT_NAME prefix here
        weechat.prnt(buffer, f'Error with command "/fish {args}" (help on command: /help fish)')
        return weechat.WEECHAT_RC_ERROR

    # list keys
    if parsed_args.command is None or parsed_args.command == 'list':
        # sort prior to displaying
        records.sort(key=attrgetter('network', 'target'))

        # list out the keys
        weechat.prnt(buffer, f'{SCRIPT_NAME}: Current Keys:')
        for record in records:

            # adding extra info to list
            extra = ''
            if record.dh:
                extra = ' (DH1080)'
            if record.cbc:
                extra += ' (CBC)'
            else:
                extra += ' (EBC)'

            # clean up key for list
            if record.key is None:
                key_str = ''
            else:
                key_str = record.key

            # display output
            weechat.prnt(buffer, f'{SCRIPT_NAME}:  {record.target}@{record.network} - "{key_str}"{extra}')
        return weechat.WEECHAT_RC_OK

    # check server (any of the following 3 commands will use server argument)
    server_check_msg = False
    connected_check_msg = False
    if parsed_args.server:
        server_check_msg = invalid_server(parsed_args.server, False)
        connected_check_msg = invalid_server(parsed_args.server, True)
        server_name = parsed_args.server
    else:
        server_name = weechat.buffer_get_string(buffer, 'localvar_server')

    # initiate key exchange
    if parsed_args.command == 'exchange':
        # we need to be connected to the server, so check now
        if connected_check_msg:
            # bad server
            weechat.prnt(buffer, f'{SCRIPT_NAME}: {connected_check_msg}')
            return weechat.WEECHAT_RC_ERROR

        # check nick
        if parsed_args.nick:
            target = parsed_args.nick
        else:
            target_type = weechat.buffer_get_string(buffer, 'localvar_type')
            if target_type == 'private':
                # local variable 'channel' will be the nickname for the query buffer
                target = weechat.buffer_get_string(buffer, 'localvar_channel')
            else:
                target = ''

        # ensure we have needed variables
        if not server_name:
            # bad server
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: A server name must be provided from this buffer.')
            return weechat.WEECHAT_RC_ERROR
        if not target:
            # bad target
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: A nickname must be provided form this buffer.')
            return weechat.WEECHAT_RC_ERROR

        # all is well, lets attempt the exchange
        record = find_or_create_record(server_name, target.lower())
        record.dh = DH1080()
        if parsed_args.old:
            weechat.prnt(buffer, f'{SCRIPT_NAME}: [fish-ebc exchange] initiating DH1080 exchange with {target}')
            record.cbc = False
        else:
            weechat.prnt(buffer, f'{SCRIPT_NAME}: [fish-cbc exchange] initiating DH1080 exchange with {target}')
            record.cbc = True
        msg = record.dh.send_request(record.cbc)

        # send the notice (no response given if not delivered)
        weechat.command(buffer, f'/mute notice -server {server_name} {target} {msg}')

        return weechat.WEECHAT_RC_OK

    # check target (either of the following 2 commands will use target argument)
    if parsed_args.target:
        target = parsed_args.target
    else:
        target_type = weechat.buffer_get_string(buffer, 'localvar_type')
        if target_type in ('channel', 'private'):
            # local variable 'channel' will be channel name or nickname for query buffer
            target = weechat.buffer_get_string(buffer, 'localvar_channel')
        else:
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: A target (nick or channel) must be provided from this buffer.')
            return weechat.WEECHAT_RC_ERROR

    # handle setting of keys
    if parsed_args.command == 'set':
        # we need to have a valid server supplied, so check now
        if server_check_msg:
            # bad server
            weechat.prnt(buffer, f'{SCRIPT_NAME}: {server_check_msg}')
            return weechat.WEECHAT_RC_ERROR

        # ensure we have needed variables
        if not server_name:
            # bad server
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: A server name must be provided from this buffer.')
            return weechat.WEECHAT_RC_ERROR
        if not target:
            # bad target
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: A target must be provided form this buffer.')
            return weechat.WEECHAT_RC_ERROR

        # check key length
        if not 8 <= len(parsed_args.key) <= 56:
            # bad key length
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: Key must be between 8 and 56 characters long.')
            return weechat.WEECHAT_RC_ERROR

        # set the key
        record = find_or_create_record(server_name, target)
        record.key = parsed_args.key
        if parsed_args.old:
            record.cbc = False
        else:
            record.cbc = True
        weechat.prnt(buffer, f'{SCRIPT_NAME}: Set "{record.target}@{record.network}" key to "{record.key}".')

        return weechat.WEECHAT_RC_OK

    # handle removal of keys
    elif parsed_args.command == 'remove':
        # ensure we have needed variables
        if not server_name:
            # bad server
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: A server name must be provided from this buffer.')
            return weechat.WEECHAT_RC_ERROR
        if not target:
            # bad target
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: A target must be provided form this buffer.')
            return weechat.WEECHAT_RC_ERROR

        # remove the key
        record = find_record(server_name, target)
        if record:
            delete_record(server_name, target)
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Removed "{target}@{server_name}" key.')
        else:
            weechat.prnt(buffer, f'{SCRIPT_NAME}: Error: Key "{target}@{server_name}" not found.')

        return weechat.WEECHAT_RC_OK

    # should never make it here
    return weechat.WEECHAT_RC_ERROR


if __name__ == '__main__' and import_ok:
    """FiSH for WeeChat
    
    Main execution begins here when the script starts. Register our script, and set the hooks we need.
    """

    # Register script.
    weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, '', '')

    # Hook /fish command.
    weechat.hook_command(
        'fish', 'initiate a key exchange or list, set, or remove FiSH keys',
        'exchange [-s|--server server] [-o|--old] [nick]\n'
        '                         list\n'
        '                         set [-s|--server server] [-t|--target target] [-o|--old] <key>\n'
        '                         remove [-s|--server server] [-t|--target target]',

        ' exchange: initiate a key exchange\n'
        '     list: list FiSH keys\n'
        '      set: manually set a key\n'
        '   remove: manually remove a key\n'
        '\n'
        'Both "server" and "target" are optional arguments. They will attempt to be determined based on which buffer '
        'the command was entered. If they cannot be determined, an error will be printed. Providing an argument will '
        'always override automatic detection.\n'
        '\n'
        'If "exchange" is entered on a query buffer "nick" will be detected.\n'
        '\n'
        'If "set" or "exchange" is provided the "old" argument then FiSH EBC mode (older) will be used.\n'
        '\n'
        'Examples:\n'
        '       CBC exchange: /fish exchange -s libera fooNick\n'
        '       EBC exchange: /fish exchange --server libera --old barNick\n'
        '    set channel key: /fish set -s foonet\n'
        ' remove channel key: /fish remove #channel\n'
        '    remove user key: /fish remove -s libera bazNick\n',

        'list'
        ' || exchange'
        ' || set'
        ' || remove',

        'fish_cmd', '')

    # Initialize/read configuration file.
    weechat.config_read(fish_config_init())

    # Hook incoming notices to process DH1080 exchanges.
    weechat.hook_modifier('irc_in2_notice', 'fish_modifier_in2_notice_cb', '')

    # Hook outgoing privmsg/notice/topic messages to encrypt.
    weechat.hook_modifier('irc_out_privmsg', 'fish_modifier_out_privmsg_cb', '')
    weechat.hook_modifier('irc_out_notice', 'fish_modifier_out_notice_cb', '')
    weechat.hook_modifier('irc_out_topic', 'fish_modifier_out_topic_cb', '')

    # Process encrypted incoming and outgoing privmsg/notice/topic messages for display in buffer.
    weechat.hook_line('', '', '*', 'fish_hook_line_cb', '')
