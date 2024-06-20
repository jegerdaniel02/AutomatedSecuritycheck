# Daniel's Automated Security Check

The steps which the script performs in that order is as follows:
* Checks if first command line parameter starts with https and exits if not
* Downloads the data file, and its accompanying signature file
* Checks the signature of file and exits if it failed
* Checks if the date in the file is the same as date of today, and exits if not
* Compares the sha256sum of the files validate and strcheck in /opt/security/bin to the provided hash in the data file. The script continues if they are the same
* Checks if the hash or string of every line starting with "IOC" and "STR" matches computed hash using the validate and strcheck tools in /opt/security/bin and alerts on a match to identify compromised files.
* Appends listening ports, current firewall rules, validates all files installed in /sbin, /bin, /usr/sbin, /usr/bin, and /usr/lib. Files which failed validation are sent to binfailure. The script then finds files in /var/www/ created in the last 48 hours. SUID/GID files are then collected to be added to the report. Filesystem mounted on /var/www/images is checked if mounted with noexec. If not, it emits a warning, and sets the noexec option, and emits a copy of file system configuration. Same is done for /var/www/uploads.
* Structures the report with appropriate headlines, and appends the files that failed validation, files created within 48 hours, and SUID/GID files in /var/www.
* Most errors are written to /opt/security/working/error.log. If error.log exists, the working directory is preserved by adding everything in the working directory to the tar file error-<\date>.tgz, excluding error.log.
* Adds relevant files to the archive file $hostname-tth-$date.tgz. Then creates a detached gpg signature using tht2023@tht.noroff.no.
* Copies the created .tgz file using rsync to the second commandline parameter, along with its signature. The 3rd commandline parameter is used to connect, with its private key in /opt/security/$3.id. Directory is  made if it doesnt exist before the copy. Lastly, a copy of the working directory is transferred if it exists.
* Uses ssh to execute the gpg --verify command on the transferred signed archive file on the remote system.
* Emits the name, size in MB, sha256 hash of the transferred archive file.
* Removes all files created.

## Installation
For the script to run, first make it executable:
```shell 
$chmod +x tth-danber86353.sh
```
1. Make sure the directories /opt/security/working and /opt/security/errors exist
2. Ensure the system can access the URL of the data file to download
3. The tools validate and strcheck must be placed in /opt/security/bin
4. Verify date and time is correct, and the command $date work as expected
5. Appropriate private and public keys must be loaded on the servers. Ssh private key file must be 
in /opt/security/useridentity.id where useridentity is 3rd command line parameter. Ensure the 
root user can access the GPG keyring, as for root, it will look for keys in roots directory. This can 
be done by adding the option “--homedir /path/to/.gnupg/” in the gpg –verify command on S3.
6. Consider the 3 command line arguments to be passed to the script in the following order;
* Server URL with path to the data files. Must start with https
* server region for uploading the report
* User identity for access to remote server

open the crontab with elevated privileges:
```shell
$ sudo crontab –e
```
* (optional) Add the line MAILTO=<email> to specify the email to get output of the script:
MAILTO=<email>
* Add the following line beneath the MAILTO command to tell crontab to run it every day at 4:30 
am, with the 3 command line parameters:
30 4 * * * /path/to/script/tth-danber86353.sh <arg1> <arg2> <arg3>