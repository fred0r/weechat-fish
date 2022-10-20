# FiSH IRC Encryption for WeeChat

## About

This is a Python 3 script for the WeeChat IRC client to add support for FiSH IRC encryption.

This script supports:

- Blowfish CBC (newer standard) encryption/decryption.
- Blowfish EBC (older standard) encryption/decryption.
- Diffie-Hellman 1080 (DH1080) key exchange.
- Encryption/decryption of PRIVMSGs to a channel or another user (IRC /msg commands).
- Encryption/decryption of ACTIONs to a channel or another user (IRC /me commands).
- Encryption/decryption of NOTICEs to a channel or another user (IRC /notice commands).
- Encryption/decryption of TOPICs on channel entry and changing while present (IRC /topic commands).
- Key management commands.
- Markers for encrypted text.

## What is FiSH?

Encryption for IRC.

## Requirements

This script requires:

- [WeeChat](https://www.weechat.org/) (3.x or better) with the python plugin
- [Python 3](https://www.python.org/) (3.9 or better)
- [PyCryptodome](https://www.pycryptodome.org/) installed in the python environment

## Installation

Download the fish.py script and place in your WeeChat python directory (~/.weechat/python).

Start WeeChat and issue `/script load fish.py` to load the script.

If no errors are reported you're done.

- Type `/help fish` to view the commands.
- All script functionality is accessed via the `/fish` command.
- All configuration options are under the `fish.` prefix (use command `/fset fish.*` to view/edit).

## Autoload

If you would like the scirpt to automatically load when WeeChat is launched, just add a symbolic link in the autoload
directory to the `fish.py` script.

`cd ~/.weechat/python/autoload && ln -s ../fish.py`

When you start WeeChat now `fish.py` should be automatically loaded.

## Diffie-Hellman 1080 (DH1080) Exchange

A Diffie-Hellman key exchange assumes that you already have authenticated communication channels between 'Alice' and
'Bob'. This assumption means that 'Alice' is certain she is communicating with 'Bob' during the exchange.

Encrypting your communications on an IRC server whose operators you do not trust is not an authenticated communication
channel. There is no reliable way for 'Alice' to tell if she really is talking to 'Bob'. It could be anyone inbetween
'Alice' and 'Bob' relaying messages (MITM attack) or an IRC server admin with a fake hostname and ident.

This means you can consider using DH1080 key exchange over IRC utterly broken in terms of security.

You can reduce the chances of this happening by verifying the key that has been set using the DH1080 exchange.

- One good option is to use an alternate form of communication (another IRC server you're both on, email, IM, text
  message, discord, zoom, etc.) to verify the key prior to disclosing anything that needs to be encrypted. Using voice
  or video chat would make it much more difficult to MITM attack the verification.

- A second less secure option (but maybe more practical) is to verify the key interactively over IRC after setting it
  via DH1080. This has a downside, that anyone 'actively relaying and present' or 'impersonating' could still bypass
  this check.

This first or second method (listed above) of key verification could be accomplished where after the DH1080 exchange one
user will send the first half of the key, and the second user would be responsible for sending the second half of the
key.

However, the second method falls apart if you're communicating with an impersonator (never authenticated in the first
place).  But it might help detect some MITM attacks unless someone is actively monitoring/altering live.

Take this advice, along with your own comfort of threat level, into consideration for your security.

## Blowfish CBC vs Blowfish EBC

The 'old' way of using FiSH IRC encryption is to use EBC (Electronic Code Book) encryption/decryption. It also uses a
custom base64 encode/decode.

The 'newer' way of using FiSH IRC encryption is to use CBC (Cipher Block Chaining) encryption/decryption. This style of
encryption uses standard base64 encode/decode.

If you encrypt a message containing "abc123" with EBC for any given key, it will be the same every time. That is, for
a key of "xyz", using EBC encryption, the output will always be the same.

This is not the case for CBC encrypted data because it uses a random IV for each block. The same message, encrypted with
the same key, will produce different output each time.

Incoming EBC encrypted lines of text will look like (lack of * on the front):

`+OK LaU9i.Os2Dc0`

Incoming CBC encrypted lines of text will look like (the * on the front denotes CBC):

`+OK *U7hBRsU0H8r/bzbzhc+QBw==`

References:

 - https://www.donationcoder.com/Software/Mouser/mircryption/help/usingcbcmode.htm
 - https://stackoverflow.com/questions/10303306/irc-blowfish-encryption-mode

## Acknowledgements

Some ideas/code/knowledge have been inspired by:

 - [Modern IRC Client Protocol](https://modern.ircdocs.horse/)

 - [Mircryption](https://www.donationcoder.com/software/mouser/other-projects/mircryption) - the addon for mIRC

 - [mirc_fish_10](https://github.com/flakes/mirc_fish_10/) - mIRC 7.x updated addon

 - [freshprinces weechat-fish plugin](https://github.com/freshprince/weechat-fish)

 - [simonzacks HexFish for XChat/HexChat](https://github.com/simonzack/hexfish)

 - py-fishcrypt (both [kwaaak](https://github.com/kwaaak/py-fishcrypt) and
   [fladd](https://github.com/fladd/py-fishcrypt))

 - [RegEx101](https://regex101.com/) - the only way to RegEx
