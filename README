-----------------------------------
  ____                  _        _ 
 / ___|_ __ _   _ _ __ | |_ ___ / |
| |   | '__| | | | '_ \| __/ _ \| |
| |___| |  | |_| | |_) | || (_) | |
 \____|_|   \__, | .__/ \__\___/|_|
            |___/|_|               
-----------------------------------
Ciaran McNally - Assignment 1 - 14/11/2013
This tool was developed as a solution to my first Cryptography assignment.

--/For help/--
./run.sh -help

--/For Sample Run/--
./sample.sh

--/Files Generated/--
my.salt -       raw byte data for the salt used in the 256-bit AES key
my.iv -         raw byte data for the IV used in AES encryption
my.aes -        raw byte data of the generated 256-bit AES Secret key
my.encrypted -  raw byte data containing the encrypted specified file
rsa.password -  password data after RSA encryption in hex
hex.salt -      salt used in the SHA-256 encryption in hex
hex.iv -        iv used in the AES encryption in hex
hex.aes -       AES 256-bit secret key in hex
hex.encrypted - Hex encryption of the file


--/Default Files/--
README -        This file!
argparser.jar - Used in assignment to parse cmd-line arguments.
Crypto1.java -  File containing assignment code
sample.sh -     This runs an example of the whole assignment, 
                generating all files. It compiles & sets the
                correct classpath.
run.sh -        This compiles & sets the classpath, runs
                accepting additional cmd-line arguments.
pubkey -        This contains the provided pubkey


--/Notes and Problems/--
There is a restriction by default on the size of the key 
you can use in certain java libraries. (if over 128-bits)
"java.security.InvalidKeyException: Illegal key size"
This problem does not occur in Open-JDK however.

I am concatenating my password and salt at a String level,
I was unsure as to whether I should have done it at a byte
level. I tested my salt/passwd combo in various online
hashing tools and my result was the same so I'm assuming
this is ok.


--/HELP OUTPUT/--
Usage: ./run.sh <params>
Ciaran McNally
Options include:

-help,-?                displays help information
-p,-password <string>   Pass in a password
-a,-aeskey              Flag to Generate our 256-bit AES key,using command-line defined password and salt
-e,-encrypt             Flag to signify AES encryption of file
-f,-file <string>       File to encrypt with AES
-x,-hex                 converts my.* files to hex equivalent hex.*
-d,-delete              Delete my.* files after hex conversion.
-k,-pubkey              Saves encrypted password to File, uses "pubkey" file.
-exp,-exponent <decimal integer>
                        Define exponent, if not defined uses default of 65537.
