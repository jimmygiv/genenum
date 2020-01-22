#!/usr/bin/env bash
#Used to install dependencies, and install the program
if [[ $(whoami) != "root" ]];
  then
echo "Run as root. I need to install stuffs maybe."
exit
fi

programs=(perl python3 pip3 git nikto dirb
ssh nbtscan ftp ruby cewl enum4linux genenum)

function installer() {
  case $1 in
    "python3")
       apt-get install python3 -y;;
    "pip3")
       apt-get install python3-pip -y;;
    "nikto")
       apt-get install nitko -y;;
    "dirb")
       apt-get install dirb -y;;
    "nbtscan")
       apt-get install nbtscan -y;;
    "ftp")
       apt-get install ftp -y;;
    "ssh")
       apt-get install ssh-client* -y;;
    "ruby")
       apt-get install ruby -y
       gem update;;
    "perl")
       apt-get install perl -y;;
    "git")
       apt-get install git -y;;
    "enum4linux")
       git clone https://github.com/portcullislabs/enum4linux
       cd enum4linux
       cp enum4linux.pl /usr/bin/enum4linux
       cd ..
       rm -rf ./enum4linux;;
    "cewl")
      apt-get install cewl;;
    "genenum")
      cp $(dirname $0)/genenum.py /usr/bin/genenum
  esac
}

#To check for core programs
for line in ${programs[@]}; do
if [[ ! $(which $line) ]];
  then
    installer $line
fi
done

echo "done"
