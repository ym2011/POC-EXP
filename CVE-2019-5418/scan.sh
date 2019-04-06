#!/bin/sh

echo "[+] Usage scan.sh [fileWithNamesOfFilesToTarget] [fileWithPathsToScan]"

filesToRead=$1
while IFS= read -r targetFile
do
        pathsToScan=$2
        while IFS= read -r path
        do
            ./CVE20195418Scanner --log=true --targets="$targetFile" --insecure=true --path="$path"
        done <"$pathsToScan"
done <"$filesToRead"