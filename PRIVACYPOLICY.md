whistle.im privacy policy
=========================
We are dedicated to the practice of, how german authorities call it, "Datensparsamkeit" (data reduction and
data economy). This means that our aim is to know and store as few data as absolutely necessary. This is
also the reason for our decision not to ask you for any personal information like your email address,
your real name or your mobile phone number. As a result you have to take care of your login data for yourself.

What we basically know about you is your possibly entirely fictitious whistle id and a bcrypt hash of your password
for authentication purposes. Everything else that we might know is some meta data and explained below. We cannot
access messages, vCards or any other sensitive information because it always becomes encrypted on your own
device. In detail:

Data transmission
-----------------
* We do not use cookies
* We use a unique token per user and session
* We do not store IP addresses
* Passwords are hashed through bcrypt prior to submission
* Passwords are rehashed with a new salt on a regular basis
* We utilize SSL/TLS between you and our servers (4096 bit)
* Encryption, decryption and hashing is done exclusively client-side
* Before your encrypted private key can be retrieved you must have authenticated through bcrypt

Data storage
------------

### User data
* **id** Your whistle id
* **pass** [bcrypt](http://en.wikipedia.org/wiki/Bcrypt) hash of your password used for authentication
* **keys** Your [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) encrypted private and plain public key
* **symkey** A randomly generated symmetric [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) key used for poll/push notifications
* **vcard** Your own vCard encrypted to yourself
* **online** Your online state (Online, Away, Busy, Offline)
* **invisible** Internal only flag if you are Invisible instead of Offline
* **created** Your account's creation time
* **loggedin** Your last log in time
* **polltime** Push/poll notification timestamp

### Contact data
* **id** Your whistle id
* **cid** Your contact's whistle respectively group id
* **state** Contact state (Pending outgoing/incoming or approved)
* **unread** Number of unread messages
* **time** Contact update timestamp
* **readtime** Last time new messages have been read at
* **vcard** Your contact's vCard encrypted to yourself (not present for pending outgoing contacts)
* **online** If a user: Your contact's online state
* **owner** If a group: Whether you are the group's owner

### Message data
* **id** Unique message id
* **from** Sender id
* **to** Recipient id
* **enc** Encrypted message from sender to recipient
* **sig** Signature for verification of the above
* **inc** Encrypted message from sender to himself
* **time** Message time

Data deletion
-------------

### Messages
Whenever you decide to delete a conversation with one of your contacts, your half of it will be immediately deleted
from our servers. This cannot be undone.

### Users
If you ever decide to delete your entire whistle account, all your data (account, keys, contacts, both sides of your
conversations) will be immediately deleted from our servers. This cannot be undone.

Data location
-------------
Our servers are located in Germany.
