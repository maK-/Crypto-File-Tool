#!/bin/bash

#Compile assignment with classpath
javac -cp "./argparser.jar:." Crypto1.java
echo "Program Compiled..."

#Generate our 256-bit AES Secret key
java -cp "./argparser.jar:." Crypto1 -a -p SimpleSample -k

#Encrypt sample.sh file
java -cp "./argparser.jar:." Crypto1 -e -f sample.sh

#Delete my.* files and create hex versions
java -cp "./argparser.jar:." Crypto1 -x -d
