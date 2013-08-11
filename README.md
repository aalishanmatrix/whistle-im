whistle.im - privacy for everyone.
==================================
The open source bits.

Contents
--------
* Client-side cryptography library

Mechanism
---------
When we started thinking about the actual cryptography algorithms that we are going to implement,
we decided to make as few trade-offs as possible. This is how it looks like today:

* PKC RSA 2048 / AES 256-CBC / RSAES-OAEP
* bcrypt authentication prior to PBKDF2
* TLS / DHE-RSA 4096 / AES 256-CBC

![overview](https://whistle.im/img/crypt.png)

License
-------
All rights reserved.
