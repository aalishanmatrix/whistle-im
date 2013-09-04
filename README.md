<div align="center">
	<img src="https://raw.github.com/whistle-im/whistle-im/master/logo/logo.png" alt="whistle.im" />
	<p>The open source bits.</p>
</div>

Contents
--------
* [Cryptography libraries](https://github.com/whistle-im/whistle-im/tree/master/client)
* [Server configurations](https://github.com/whistle-im/whistle-im/tree/master/server)
* [Language files](https://github.com/whistle-im/whistle-im/tree/master/i18n)

Wiki
----
* [Frequently Asked Questions](https://github.com/whistle-im/whistle-im/wiki/Frequently-Asked-Questions)
* [Encryption Mechanism](https://github.com/whistle-im/whistle-im/wiki/Encryption-Mechanism)
* [Privacy Policy](https://github.com/whistle-im/whistle-im/wiki/Privacy-Policy)

Internationalization
--------------------
For now we have translated the app and the website from English, which is the default language
used in the sources, to German. You can find all current translations in `i18n/LANGUAGECODE.json`.
Pull requests, even for entire languages, are welcome!

In case you intend to extend whistle.im with your native language, please review our [Contributor
License Agreement](https://github.com/whistle-im/whistle-im/blob/master/CLA) (CLA) before you start.

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

License
-------
whistle.im cryptography library
Copyright (C) 2013 Daniel Wirtz - http://dcode.io

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see: http://www.gnu.org/licenses/

Imprint
-------
whistle.im c/o Daniel Wirtz, Michael Bank  
An der Zikkurat 4, 53894 Mechernich, Germany  
mail: whistle@whistle.im, web: https://whistle.im, tel: +49 174 8514016  
USt-IdNr. gem. § 27 a UstG: DE262739457
