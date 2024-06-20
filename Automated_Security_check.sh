#!/bin/bash

# This script was created with assistance from ChatGPT.
# Script Author: Daniel Bergan
# Inputs: This script expects 3 command line parameters; URL of IOC file to \
# download, remote server for upload, and the user identity, respectively.
#k2 Checks if first commandline parameter URL is https

url="$1"
if [[ "$url" == https* ]]; then
    echo "K2: HTTPS protocol verified"
else
    echo "Not a secure protocol. exiting"
    exit
fi

#S2 Downloads IoC file using wget and assigns it to $thefile
timestamp=$(date +%Y%m%d-%H:%M)
hostname=$(hostname)
current_date=$(date +"%Y%m%d")
thefile2="IOC-${current_date}.ioc"
opt_sec_work=opt/security/working
wget --no-check-certificate -q -P /$opt_sec_work/ "$1/$thefile2"
if [ $? -eq 0 ]; then
    echo "S2: File downloaded: $thefile2"
else
    echo "FAILED S2-$hostname $timestamp"
    echo "File failed to download. exiting"
    exit
fi
wget --no-check-certificate -q -P /$opt_sec_work/ "$1/IOC-${current_date}.gpg"
thefile=/$opt_sec_work/IOC-${current_date}.ioc

#S3 Validates integrity. Sets the relevant files as variables then uses gpg verify

gpgpath=$(which gpg)
signature=/$opt_sec_work/"IOC-${current_date}.gpg"
"$gpgpath" --verify "$signature" "$thefile" >> /dev/null 2>> /$opt_sec_work/error.log
# Checks if exit status of last executed command is 0; successfull
if [ $?  -eq 0 ]; then
    echo "S3: Signature verified."
else
    echo "FAILED S3-$hostname $timestamp"
    echo "Signature not verified. exiting"
    exit
fi

#S4 Validates date today with date found on 2nd line in IoC file. The date in \
# the file is checked of length, and zero padded accordingly to be compared.
thedate="$(date +'%Y-%m-%d')"
file_date=$(cat "$thefile" | awk 'NR==2')
length=${#file_date}
month="${file_date:4:2}"

if [[ $length == 7 && $month -gt 12 ]]; then
    year="${file_date:0:4}"
    month="${file_date:4:1}"
    day="${file_date:5:2}"
    formatted_day=$(printf "%02d" "$day")
    formatted_month=$(printf "%02d" "$month")
elif [[ $length == 7 ]]; then
    year="${file_date:0:4}"
    month="${file_date:4:2}"
    day="${file_date:6:2}"
    formatted_day=$(printf "%02d" "$day")
    formatted_month=$(printf "%02d" "$month")

elif [[ $length == 6 ]]; then
    year="${file_date:0:4}"
    month="${file_date:4:1}"
    formatted_month=$(printf "%02d" "$month")
    day="${file_date:5:1}"
    formatted_day=$(printf "%02d" "$day")
elif [[ $length == 8 ]]; then
    year="${file_date:0:4}"
    month="${file_date:4:2}"
    day="${file_date:6:2}"
    formatted_month=$month
    formatted_day=$day
fi
file_date_2="${year}-${formatted_month}-${formatted_day}"

if [[ "$thedate" == "$file_date_2" ]]; then
    echo "S4: Filedate verified"
else
    echo "FAILED S4-$hostname $timestamp"
    echo "Date of file is not of today. exiting"
    exit
fi

#S5 Compares validate and strcheck hashes from the IOC file to their sha256sum
validate_hash=$(sha256sum /opt/security/bin/validate | awk -F" " '{print$1}')
validate_str=$(sha256sum /opt/security/bin/strcheck | awk -F" " '{print$1}')
expected_hash=$(cat "$thefile" | grep -w VALIDATE |  awk -F" " '{print$2}')
expected_str=$(cat "$thefile" | grep -w STRCHECK |  awk -F" " '{print$2}')

if [[ "$expected_hash" == "$validate_hash" && ${#expected_hash} -gt 1 ]]; then
    echo "S5: VALIDATE hash is validated"
else
    echo "FAILED S5-$hostname $timestamp"
    echo "VALIDATE hash was not validated. exiting"
    exit
fi

if [[ "$expected_str" == "$validate_str" && ${#expected_hash} -gt 1 ]]; then
    echo "S5: STRCHECK hash is validated"
else
    echo "FAILED S5-$hostname $timestamp"
    echo "STRCHECK hash was not validated. exiting"
    exit
fi

#S8 checks if the hash or string of every line starting with IOC and STR is inside the directory on that line
IOClines=$(cat "$thefile" | grep -w ^IOC | grep -v \#)
IFS=$'\n'
#FOR THE VALIDATE SPECIALIST FILE:
for line in $IOClines; do
    line_dir=$(echo "$line" | cut -c 70-)
    line_hash=$(echo "$line" | cut -c 5- | awk -F" " '{print$1}')
    find $line_dir -type f -exec /opt/security/bin/validate {} \; 2>>/$opt_sec_work/error.log | while IFS=' ' read -r hash matchingfile; do
        if [[ $hash == $line_hash ]]; then
            echo "$line_hash" >> /$opt_sec_work/tmp.log
            echo "WARN: IOCHASHVALUE $matchingfile"
        fi
    done
done
#FOR THE STRCHECK SPECIALIST FILE:
IFS=$'\n'
STRlines=$(cat "$thefile" | grep -w ^STR | grep -v \# | tail -n +2)
for line in $STRlines; do
    thedir=$(echo "$STRlines" | awk -F" " '{print$3}')
    thestring=$(echo "$STRlines" | awk -F" " '{print$2}')
    find $thedir -type f -exec /opt/security/bin/strcheck {} \; 2>>/$opt_sec_work/error.log | while IFS=' ' read -r string MatchingStrFile; do
        if [[ $string == $thestring ]]; then
            echo "$thestring" >> /$opt_sec_work/tmp.log
            echo "WARN: STRVALUE $MatchingStrFile"
        fi
    done
done

#S9 appends listening ports, current firewall rules, validates all files installed in /sbin, /bin, /usr/sbin, \
# /usr/bin, and /usr/lib. Files which failed validation are sent to binfailure. The script then finds files \
# in /var/www/ created in the last 48 hours. SUID/GID files are then collected to be added to the report.
# Filesystem mounted on /var/www/images is checked if mounted with noexec. If not, it emits a warning, and \
# sets the noexec option, and emits a copy of file system configuration. Same is done for /var/www/uploads.

netstat -tuln >> /$opt_sec_work/listeningports
iptables -L -n >> /$opt_sec_work/firewall
#find /sbin /bin /usr/sbin /usr/bin /usr/lib  -type f > /$opt_sec_work/debsums.tmp
while IFS= read -r line; do
    dpkg -S "$line" >> /$opt_sec_work/debsums2.tmp 2>>/$opt_sec_work/error.log
done < /$opt_sec_work/debsums.tmp
availablecores=$(nproc)
# utilizes available cores to speed up the process
awk -F':' '{print $1}' /$opt_sec_work/debsums2.tmp | sort | uniq | xargs -P "$availablecores" -n 1 debsums -c 2>>/$opt_sec_work/error.log > /$opt_sec_work/binfailure
find /var/www/ -ctime -2 > /opt/security/working/files_.tmp
find /var/www/ -type f -perm /4000 > /$opt_sec_work/SUID.tmp
find /var/www/ -type f -perm /2000 > /$opt_sec_work/GID.tmp

date=$(date +"%Y%m%d")
echo -e "=== IOC Report: $date ===\n" > /$opt_sec_work/iocreport-$date.txt
echo "1. File System Configuration:" >> /$opt_sec_work/iocreport-$date.txt
mount | grep /var/www/images | grep -q noexec
if [[ $? -eq 0 ]]; then
    true
else
    echo "WARNING: noexec is not set on file system mounted on /var/www/images. remounting with noexec"
    echo "WARNING: noexec is not set on file system mounted on /var/www/images" >> /$opt_sec_work/iocreport-$date.txt
    mount -o remount,noexec /var/www/images
    echo "System configuration for mounting filesystems:" >> /$opt_sec_work/iocreport-$date.txt
    echo "$(cat /etc/fstab | grep -v \#)" >> /$opt_sec_work/iocreport-$date.txt
fi
mount | grep /var/www/uploads | grep -q noexec
if [[ $? -eq 0 ]]; then
    true
else
    echo "WARNING: noexec is not set on file system mounted on /var/www/uploads. remounting with noexec"
    echo "WARNING: noexec is not set on file system mounted on /var/www/uploads" >> /opt/security/working/iocreport-$date.txt
    mount -o remount,noexec /var/www/images
    echo "System configuration for mounting filesystems:" >> /$opt_sec_work/iocreport-$date.txt
    echo "$(cat /etc/fstab | grep -v \#)" >> /$opt_sec_work/iocreport-$date.txt
fi

#S10 Merges relevant files into the report, and structures the report.
echo -e "\n2. Files which failed validation:" >> /$opt_sec_work/iocreport-$date.txt

cat /opt/security/working/binfailure >> /$opt_sec_work/iocreport-$date.txt 2>>/$opt_sec_work/error.log

echo -e "\n3. Files created within 48 hours:" >> /$opt_sec_work/iocreport-$date.txt
cat /opt/security/working/files_.tmp >> /$opt_sec_work/iocreport-$date.txt 2>>/$opt_sec_work/error.log

echo -e "\n4. SUID/GID files in var/www:\n" >> /$opt_sec_work/iocreport-$date.txt
cat /opt/security/working/SUID.tmp >> /$opt_sec_work/iocreport-$date.txt 2>>/$opt_sec_work/error.log
cat /opt/security/working/GID.tmp >> /$opt_sec_work/iocreport-$date.txt 2>>/$opt_sec_work/error.log

#S7 If error.log exists, the working directory is preserved by adding everything in the directory to \
# error-$date.tgz, excluding error.log.
if [[ -e "/$opt_sec_work/error.log" ]]; then
    cd /opt/security/working/
    tar -czf /opt/security/errors/error-$date.tgz --exclude="error.log" .
else
    true
fi

#S10 Adds relevant files to the archive file $hostname-tth-$date.tgz. Then creates a detached gpg \
# signature using tht2023@tht.noroff.no.
hostname=$(hostname)
cd /$opt_sec_work/
tar --ignore-failed-read -cf $hostname-tth-$date.tgz listeningports firewall binfailure iocreport-$date.txt /opt/security/errors/error-$date.tgz 2>>/$opt_sec_work/error.log
tgz_file=$hostname-tth-$date.tgz
"$gpgpath" --detach-sign --local-user tht2023@tht.noroff.no --output $tgz_file.gpg /$opt_sec_work/$tgz_file

#S11 Copies the created .tgz file using rsync to the second commandline parameter, along with its signature.
# The 3rd commandline parameter is used to connect, with its private key in /opt/security/$3.id. Directory \
# is  made if it doesnt exist before the copy. Lastly, a copy of the working directory is transferred if it exists.
year=$(date +%Y)
month=$(date +%m)
ssh -o StrictHostKeyChecking=no -i /opt/security/$3.id $3@$2 "[ -d submission/$hostname/$year/$month ] || mkdir -p submission/$hostname/$year/$month" 2>>/$opt_sec_work/error.log
rsync -e "ssh -o StrictHostKeyChecking=no -i /opt/security/$3.id" /$opt_sec_work/$tgz_file $3@$2:/submission/$hostname/$year/$month/ 2>>/$opt_sec_work/error.log
rsync -e "ssh -o StrictHostKeyChecking=no -i /opt/security/$3.id" /$opt_sec_work/$tgz_file.gpg $3@$2:/submission/$hostname/$year/$month/ 2>>/$opt_sec_work/error.log
rsync -e "ssh -o StrictHostKeyChecking=no -i /opt/security/$3.id" /opt/security/errors/error-$date.tgz $3@$2:/submission/$hostname/$year/$month/ 2>>/$opt_sec_work/error.log

#S12 Uses ssh to execute the gpg --verify command on the transferred signed archive file on the remote system.
ssh -i /opt/security/$3.id $3@$2 "gpg --yes --verify /submission/$hostname/$year/$month/$tgz_file.gpg /submission/$hostname/$year/$month/$tgz_file" 2>>/>

#S13 Emits the name, size in MB, sha256 hash of the transferred archive file.
file_bytes=$(stat -c %s /$opt_sec_work/$tgz_file)
echo "file bytes $file_bytes"
to_divide=$((1024 * 1024))
file_mb=$(echo "scale=2; $file_bytes / $to_divide" | bc)
echo "file mb $file_mb"
rounded_file_mb=$(printf "%.0f" "$file_mb")
file_hash=$(sha256sum /$opt_sec_work/$tgz_file | awk -F" " '{print$1}')
echo "S13 Name: $tgz_file"
echo "S13 Size of upload: $rounded_file_mb MB"
echo "S13 Sha256hash: $file_hash"
echo "TTH IoC Check for $hostname $timestamp OK"

#S16 Removes all files created.
rm /$opt_sec_work/files_.tmp
rm /$opt_sec_work/GID.tmp
rm /$opt_sec_work/SUID.tmp
rm /$opt_sec_work/IOC-$date.ioc
rm /$opt_sec_work/IOC-$date.ioc.gpg
rm /$opt_sec_work/tmp.log
rm /$opt_sec_work/listeningports
rm /$opt_sec_work/firewall
rm /$opt_sec_work/binfailure
rm /$opt_sec_work/$hostname-tth-$date.tgz