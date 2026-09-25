@echo off
if exist target\classes rmdir /s /q target\classes
mkdir target\classes
dir /s /b src\main\java\*.java > sources.txt
javac --release 17 -d target\classes @sources.txt
if errorlevel 1 exit /b 1
del sources.txt
jar --create --file target\baitcheck.jar --main-class com.baitcheck.Main -C target\classes .
echo Built target\baitcheck.jar
echo Try: java -jar target\baitcheck.jar samples\
