<div align="center">
	<img src="https://raw.github.com/whistle-im/whistle-im/master/logo/logo.png" alt="whistle.im" />
	<p>The open source bits.</p>
</div>

Contents
--------
* [Client-side cryptography library](https://github.com/whistle-im/whistle-im/tree/master/crypt)
* [Client language files](https://github.com/whistle-im/whistle-im/tree/master/i18n)
* Platform specific code
* [Privacy policy](https://github.com/whistle-im/whistle-im/blob/master/PRIVACYPOLICY.md)

Encryption mechanism
--------------------
When we started thinking about the actual cryptography algorithms that we are going to implement,
we decided to make as few trade-offs as possible. This is how it looks like today:

* PKC RSA 2048 / AES 256-CBC / RSAES-OAEP
* bcrypt authentication prior to PBKDF2 retrieval
* TLS / DHE-RSA 4096 / AES 256-CBC

![overview](https://whistle.im/img/crypt.png)

Internationalization
--------------------
For now we have translated the app and the website from English, which is the default language
used in the sources, to German. You can find all current translations in `i18n/LANGUAGECODE.json`.
Pull requests, even for entire languages, are welcome!

In case you intend to extend whistle.im with your native language, please review our [Contributor
License Agreement](https://github.com/whistle-im/whistle-im/blob/master/CLA.md) (CLA) before you start.

Translations are simple JSON files containing mappings of English words and sentences to your native
language. Some values use placeholders like `%name%` which must not be translated but kept as is.
These will later be replaced with the actual information that belongs there. Some values also use
HTML tags like `<strong>` or similar. These must not be changed in any way but kept as is. Language
files must use UTF8 encoding and be valid JSON.

To create a new language, just fork our repository, add your language file and send us a pull
request. If you do not know how to do this, you can also send us your translation by email. We
will take care of it then.

Whenever you are contributing (to) a language, please state that you have read and agreed to our
CLA mentioned above.

Thank you!

Platform specific code
----------------------
There are currently some pending tasks that are required to launch apps for
the different platforms like iOS, Windows Phone or BlackBerry. If you are a programmer and would
like to contribute to our development, you can freely pick from the following tasks. Please read and
agree to our CLA mentioned above. Everything else, like if your code will be open source or not, is
entirely up to you as the original author.

### All platforms except Android &amp; HTML5

* **genkeys** Generate 2048 Bit RSA private and public key pairs (PEM format)
* **base64encode/decode** Convert a variable number of bytes to/from base64
* **rsaesoaepEncrypt** Encrypt raw bytes using RSAES-OAEP using a PEM formatted public key
* **rsaesoaepDecrypt** Decrypt the above back to raw bytes using a PEM formatted private key
* **genaeskey** Generate a cryptographically secure random 256 bit / 32 byte key
* **aesEncrypt** Encrypt a variable length of raw bytes through AES-256-CBC with PKCS#7 padding
* **aesDecrypt** Decrypt the AES-256-CBC with PKCS#7 encrypted bytes from above

Usually a code-snipped will already be sufficient and save us lots of research time. Just send us
a pull request for `native/PLATFORM/TASK` or send us an email.

Thank you!

Contributors
------------
[Daniel Wirtz](https://github.com/dcodeIO/)

License
-------
All rights reserved. All contributions are properties of their respective owners.

Imprint
-------
whistle.im c/o Daniel Wirtz, Michael Bank
An der Zikkurat 4
53894 Mechernich, Germany
mail: whistle@whistle.im
web: https://whistle.im
USt-IdNr. gem. § 27 a UstG: DE262739457
