#!/bin/bash

#Compile each time
javac -cp "./argparser.jar:." Crypto1.java

#run program with arguments
java -cp "./argparser.jar:." Crypto1 $*
