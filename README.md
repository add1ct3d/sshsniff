# sshsniff
sniff ssh username and password when ssh connection comes in.
username and password are logged in file prod-user-password .

please run this script as daemon :
```
nohup python sshsniff.py >> prod-user-password  &
```
