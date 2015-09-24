#!/usr/lib/ocf/resource.d/aws/.env/bin/python2.7
#code: utf-8
import boto.ec2
import time
import ConfigParser
import sys
import base64
import logging
import re
import os

LOG_FILENAME = "run.log"
logFormatter = logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fileHandler = logging.FileHandler(LOG_FILENAME)
fileHandler.setLevel(logging.DEBUG)
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)
consoleHandler = logging.StreamHandler(stream=sys.stdout)
consoleHandler.setLevel(logging.INFO)
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

OCF_SUCCESS=0
OCF_ERR_GENERIC=1
OCF_ERR_ARGS=2
OCF_ERR_UNIMPLEMENTED=3
OCF_ERR_PERM=4
OCF_ERR_INSTALLED=5
OCF_ERR_CONFIGURED=6
OCF_NOT_RUNNING=7


def main():
    logger.debug('Spawned')
    if len(sys.argv)==1:
        print 'Usage %s [monitor | start | stop | meta-data]' % sys.argv[0]
        exit()
    if sys.argv[1]=='monitor':
        get_env()
        connect_to_aws()
        return monitor(ip_addr, my_instance_id)
    elif sys.argv[1]=='start':
        lock_timeout = 10
        lockfile = "/var/lock/privateip_ra"
        if os.path.isfile(lockfile):
            file_mtime = os.path.getmtime(lockfile)
            time_local = time.time()
            if ((file_mtime+lock_timeout) < time_local):
                logger.debug("Lock expired, remove lock and create own")
                os.remove(lockfile)
                os.mknod(lockfile, 600)
                get_env()
                connect_to_aws()
                status = start(ip_addr, my_instance_id)
                os.remove(lockfile)
                return status
            else:
                logger.debug("Lock active, waiting...")
                timeout = time_local + lock_timeout
                while True:
                    if time.time() > timeout:
                        logger.debug("We can not wait any longer. Exiting.")
                        return OCF_ERR_GENERIC
                    if not os.path.isfile(lockfile):
                        os.mknod(lockfile, 600)
                        get_env()
                        connect_to_aws()
                        status = start(ip_addr, my_instance_id)
                        os.remove(lockfile)
                        return status
        else:
            os.mknod(lockfile, 600)
            get_env()
            connect_to_aws()
            status = start(ip_addr, my_instance_id)
            os.remove(lockfile)
            return status
    elif sys.argv[1]=='stop':
        get_env()
        connect_to_aws()
        return stop(ip_addr)
    elif sys.argv[1]=='meta-data':
        metadata()
    else:
        logger.debug('No parameter sent')
        print 'Usage %s [monitor] [start] [stop] [meta-data]' % sys.argv[0]
        exit()


def connect_to_aws():
    config = ConfigParser.ConfigParser()
    config.read("/etc/corosync/privateip-ra.conf")
    conf_opts_list = {'aws_access_key_id': None,
                    'aws_secret_access_key': None,
                    'aws_region': None,
                    }
    for option in conf_opts_list.keys():
        try:
            conf_opts_list[option] = config.get('main', option)
        except ConfigParser.NoOptionError:
            sys.exit("%s in main section not set" % option)
    params_ec2conn = {
                'aws_access_key_id':conf_opts_list['aws_access_key_id'],
                'aws_secret_access_key':conf_opts_list['aws_secret_access_key'],
                }
    region = conf_opts_list['aws_region']

    global conn
    conn = boto.ec2.connect_to_region(region,**params_ec2conn)


def get_env():
    global ip_addr
    global resource_name
    global my_instance_id
    global ocf_env
    ocf_env = {}
    resource_name = None
    my_instance_id = os.popen('ec2metadata --instance-id').read().rstrip()
    env = os.environ
    for key in env.keys():
        if key.startswith("OCF_"):
            ocf_env[key] = env[key]
    try:
        if ocf_env['OCF_RESOURCE_INSTANCE'] is not None:
            resource_name = ocf_env['OCF_RESOURCE_INSTANCE']
    except:
        pass
    try:
        if ocf_env['OCF_RESKEY_address'] is not None:
            ip_addr = ocf_env['OCF_RESKEY_address']
    except:
        logger.debug('Mandatory variable (OCF_RESKEY_address, OCF_RESOURCE_INSTANCE) not set')
        exit(1)


def monitor(ip_addr, instance_id):
    logger.info('Execute command monitor %s %s',ip_addr,resource_name)
    try:
        reservations = \
        conn.get_all_reservations(instance_ids=my_instance_id)
    except:
        return OCF_ERR_GENERIC
    for reservation in reservations:
        ip_list=[]
        list_ip_on_interface = get_local_ifaces()
        for iface in reservation.instances[0].interfaces:
            for ip in iface.private_ip_addresses:
                addr = re.findall("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", str(ip))[0]
                ip_list.append(addr)
        print reservation.instances[0].id, ip_list
        if (ip_addr in ip_list and addr in list_ip_on_interface):
            logger.info('RUNNING %s' % ip_addr)
            return OCF_SUCCESS
        else:
            logger.info('NOT RUNNING %s' % ip_addr)
            return OCF_NOT_RUNNING

def get_local_ifaces():
    cmd_iplist = 'ip a sh dev eth0'
    output = os.popen(cmd_iplist).read()
    output = re.findall("inet \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}",output)
    list_ip_on_interface = []
    for addr in output:
        addr = addr.replace('inet ','')
        list_ip_on_interface.append(addr)
    logger.debug("List local iface addresses: %s" % list_ip_on_interface)
    return list_ip_on_interface

def start(ip_addr, instance_id):
    logger.info('Execute command start %s %s',ip_addr,resource_name)
    try:
        addr_status = monitor(ip_addr, instance_id)
    except:
        logger.info('Some shit happens when we start %s' % ip_addr)
        return OCF_ERR_GENERIC
    if addr_status == OCF_SUCCESS:
        logger.info('Do none, all OK %s' % ip_addr)
        return OCF_SUCCESS
    elif addr_status == OCF_NOT_RUNNING:
        try:
            logger.info('Detach address from foreign instance (if attached) %s',ip_addr)
            stop(ip_addr)
        except:
            logger.info('Detach failed %s' % ip_addr)
            return OCF_ERR_GENERIC
        try:
            logger.info('Assign address to me %s' % ip_addr)
            return ip_assign_brain(ip_addr, instance_id)
        except:
            logger.info('Assign failed %s' % ip_addr)
            return OCF_ERR_GENERIC
    else:
        logger.info('Start failed %s' % ip_addr)
        return OCF_ERR_GENERIC

def ip_assign_brain(ip_addr, instance_id):
    try:
        return ip_assign_private_brain(ip_addr, instance_id)
        logger.info('Private addr sucessfully assigned')
    except:
        logger.info('Private addr assign failed')
        return OCF_ERR_GENERIC 

def ip_assign_private_brain(ip_addr, instance_id):
    try:
        return ip_assign_private_brain_stage2_exist(ip_addr, instance_id)
    except:
        logger.error('Some shit happened %s' % ip_addr)
        return OCF_ERR_GENERIC

def ip_assign_private_brain_stage2_exist(ip_addr, instance_id):
    list_ip_on_interface = get_local_ifaces()
    if any(ip_addr in s for s in list_ip_on_interface):
        logger.info('Private addr exist on network interface')
        return ip_assign_private_brain_stage3_attach(ip_addr, instance_id)
    else:
        logger.info('Private addr not exist on network interface')
        try:
            os.system('ip addr add %s/18 dev eth0' % ip_addr)
            logger.info('Private addr was added')
            return ip_assign_private_brain_stage3_attach(ip_addr, instance_id)
        except:
            logger.error('Cant add private addr to interface eth0')
            return OCF_ERR_GENERIC

def ip_assign_private_brain_stage3_attach(ip_addr, instance_id):
    instances = conn.get_only_instances(instance_ids=instance_id)
    interface_id = instances[0].interfaces[0].id
    try:
        conn.assign_private_ip_addresses(network_interface_id=interface_id, \
                private_ip_addresses=ip_addr, allow_reassignment=True)
        logger.info('Private addr was assigned')
        return OCF_SUCCESS
    except:
        logger.error('Some error occured when we try to assign private addr')
        return OCF_ERR_GENERIC

def stop(ip_addr):
    logger.info('Execute command stop %s %s',ip_addr,resource_name)
    try:
        logger.info('Detach success %s' % ip_addr)
        return OCF_SUCCESS
    except:
        logger.info('Detach failed %s' % ip_addr)
        return OCF_SUCCESS

def metadata():
    logger.debug('Execute command meta-data')
    env=r'''<?xml version="1.0"?>
<!DOCTYPE resource-agent SYSTEM "ra-api-1.dtd">
<resource-agent name="privateip.py">
<version>0.1</version>
<longdesc lang="en">AWS EC2 PIP RA</longdesc>
<shortdesc lang="en">AWS EC2 PIP RA</shortdesc>
<parameters>
<parameter name="address" unique="1" required="1">
<longdesc lang="en">IP address</longdesc>
<shortdesc lang="en">IP</shortdesc>
<content type="string" default=""/>
</parameter>
</parameters>
<actions>
<action name="start"        timeout="10" />
<action name="stop"         timeout="20" />
<action name="monitor"      timeout="10" />
<action name="meta-data"    timeout="5" />
</actions>
</resource-agent>

'''
    print env

if __name__ == '__main__':
    sys.exit(main())

