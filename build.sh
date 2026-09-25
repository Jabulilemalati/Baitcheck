#!/usr/bin/env sh
set -e
rm -rf target/classes
mkdir -p target/classes
javac --release 17 -d target/classes $(find src/main/java -name '*.java')
jar --create --file target/baitcheck.jar --main-class com.baitcheck.Main -C target/classes .
echo "Built target/baitcheck.jar"
echo "Try: java -jar target/baitcheck.jar samples/"
