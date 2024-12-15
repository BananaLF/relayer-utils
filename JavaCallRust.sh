set -e
#1. complie rust link

#if you got some link error related platform,
# you can custom build yourself lib.
cargo build
# macos suffix is dylib
# linux suffix is so
cp ./target/debug/librelayer_utils.dylib ./javalib

#2. complie java
javac ZKEmails.java

#3. run java
java -Djava.library.path=./javalib ZKEmails