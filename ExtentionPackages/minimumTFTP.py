"""
Minimum TFTP server & client.
Support only RFC 1350. No ascii mode.
Python3.x.

version 20110917

usage:
----------------------------------------------
>>> import minimumTFTP

## server running
>>> tftpServer = minimumTFTP.Server('C:\\server_TFTP_Directory')
>>> tftpServer.run()

## client running
##  arg1: server_IP_address
##  arg2: client_directory
##  arg3: get or put filename
>>> tftpClient = minimumTFTP.Client(arg1, arg2, arg3)

## get
>>> tftpClient.get()

## put
>>> tftpClient.put()
----------------------------------------------
"""

import socket
import struct
import os
import re
import time
import threading
import sys

class Server:
    def __init__(self, dPath):
        global serverDir, serverLocalSocket, remoteDict
        serverDir = dPath
        serverLocalSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serverLocalSocket.bind(('', 69))
        remoteDict = {}

    def run(self):
        while True:

            try:
                data, remoteSocket = serverLocalSocket.recvfrom(4096)

                if remoteSocket in remoteDict:
                    remoteDict[remoteSocket].runProc(data)
                else:
                    remoteDict[remoteSocket] = packetProcess(remoteSocket)
                    remoteDict[remoteSocket].runProc(data)

            except:
                pass


class watchdog(threading.Thread):
    def __init__(self, owner):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.resetEvent = threading.Event()
        self.stopEvent = threading.Event()
        self.owner = owner

    def run(self):
        timeCount = 0

        while True:

            if self.stopEvent.isSet():
                break

            if timeCount % 5 == 0 and 0 < timeCount < 25:
                remoteDict[self.owner].reSend()
                print('Resend data.(%s:%s)' %(self.owner[0], self.owner[1]))

            elif timeCount >= 25:
                remoteDict[self.owner].clear('Session timeout. (%s:%s)' \
                                             %(self.owner[0], self.owner[1]))
                break

            if self.resetEvent.isSet():
                timeCount = 0
                self.resetEvent.clear()

            time.sleep(1)
            timeCount += 1


    def countReset(self):
        self.resetEvent.set()


    def stop(self):
        self.stopEvent.set()


class packetProcess:
    def __init__(self, remoteSocket):
        self.remoteSocket = remoteSocket
        self.endFrag = False
        self.watchdog = watchdog(self.remoteSocket)

    def runProc(self, data):
        self.watchdog.countReset()
        Opcode = struct.unpack('!H', data[0:2])[0]

        ##Opcode 1 [ Read request ]
        ##
        ##          2 bytes    string   1 byte     string   1 byte
        ##          -----------------------------------------------
        ##   RRQ   |  01   |  Filename  |   0  |    Mode    |   0  |
        ##          -----------------------------------------------

        if Opcode == 1:

            filename = bytes.decode(data[2:].split(b'\x00')[0])
            filePath = os.path.join(serverDir, filename)
            print('Read request from:%s:%s, filename:%s' \
                  %(self.remoteSocket[0], self.remoteSocket[1],filename))

            if os.path.isfile(filePath):
                try:
                    self.sendFile = open(filePath, 'rb')
                except:
                    serverLocalSocket.sendto(errFileopen, self.remoteSocket)
                    self.clear('Can not read file. Session closed. (%s:%s)' \
                               %(self.remoteSocket[0], self.remoteSocket[1]))
                    return None

                dataChunk = self.sendFile.read(512)
                self.totalDatalen = len(dataChunk)
                self.countBlock = 1

                self.sendPacket = struct.pack(b'!2H', 3, self.countBlock) \
                                              + dataChunk
                serverLocalSocket.sendto(self.sendPacket, self.remoteSocket)

                if len(dataChunk) < 512:
                    self.endFrag = True

                self.watchdog.start()

            else:
                serverLocalSocket.sendto(errNofile, self.remoteSocket)
                self.clear('Requested file not found. Session closed. (%s:%s)' \
                           %(self.remoteSocket[0], self.remoteSocket[1]))


        ##Opcode 2 [ Write request ]
        ##
        ##          2 bytes    string   1 byte     string   1 byte
        ##          -----------------------------------------------
        ##   WRQ   |  02   |  Filename  |   0  |    Mode    |   0  |
        ##          -----------------------------------------------


        elif Opcode == 2:

            filename = bytes.decode(data[2:].split(b'\x00')[0])
            filePath = os.path.join(serverDir, filename)
            print('Write request from:%s:%s, filename:%s' \
                  %(self.remoteSocket[0], self.remoteSocket[1], filename))

            if os.path.isfile(filePath):
                serverLocalSocket.sendto(errFileExists, self.remoteSocket)
                self.clear('File already exist. Session closed. (%s:%s)' \
                           %(self.remoteSocket[0], self.remoteSocket[1]))

            else:
                try:
                    self.rcvFile = open(filePath, 'wb')
                except:
                    serverLocalSocket.sendto(errFileopen, self.remoteSocket)
                    self.clear('Can not open file. Session closed. (%s:%s)' \
                               %(self.remoteSocket[0], self.remoteSocket[1]))
                    return None

                self.totalDatalen = 0
                self.countBlock = 1

                self.sendPacket = struct.pack(b'!2H', 4, 0)
                serverLocalSocket.sendto(self.sendPacket, self.remoteSocket)

                self.watchdog.start()


        ##Opcode 3 [ Data ]
        ##
        ##          2 bytes    2 bytes       n bytes
        ##          ---------------------------------
        ##   DATA  | 03    |   Block #  |    Data    |
        ##          ---------------------------------

        elif Opcode == 3:

            blockNo = struct.unpack('!H', data[2:4])[0]
            dataPayload = data[4:]
            self.totalDatalen += len(dataPayload)

            if blockNo == self.countBlock:
                try:
                    self.rcvFile.write(dataPayload)
                except:
                    serverLocalSocket.sendto(errFilewrite, self.remoteSocket)
                    self.clear('Can not write data. Session closed. (%s:%s)' \
                               %(self.remoteSocket[0], self.remoteSocket[1]))
                    return None

                self.countBlock += 1
                if self.countBlock == 65536:
                    self.countBlock = 0

                self.sendPacket = struct.pack(b'!2H', 4, blockNo)
                serverLocalSocket.sendto(self.sendPacket, self.remoteSocket)

                self.watchdog.countReset()

                if len(dataPayload) < 512:
                    self.clear('Data receive finish. %s bytes (%s:%s)' \
                               %(self.totalDatalen, self.remoteSocket[0],
                                 self.remoteSocket[1]))

            else:
                print('Receive wrong block. Resend data. (%s:%s)'
                      %(self.remoteSocket[0], self.remoteSocket[1]))


        ##Opcode 4 [ ack ]
        ##
        ##          2 bytes    2 bytes
        ##          -------------------
        ##   ACK   | 04    |   Block #  |
        ##          --------------------

        elif Opcode == 4:

            if self.endFrag:
                self.clear('Data send finish. %s bytes (%s:%s)' \
                           %(self.totalDatalen, self.remoteSocket[0],
                             self.remoteSocket[1]))

            else:
                blockNo = struct.unpack('!H',data[2:4])[0]

                if blockNo == self.countBlock:
                    try:
                        dataChunk = self.sendFile.read(512)
                    except:
                        dataChunk = ''

                    dataLen = len(dataChunk)
                    self.totalDatalen += dataLen
                    self.countBlock += 1
                    if self.countBlock == 65536:
                        self.countBlock = 0

                    self.sendPacket = struct.pack(b'!2H', 3, self.countBlock) \
                                                  + dataChunk
                    serverLocalSocket.sendto(self.sendPacket, self.remoteSocket)

                    self.watchdog.countReset()

                    if dataLen < 512:
                        self.endFrag = True

                else:
                    print('Receive wrong block. Resend data. (%s:%s)'
                          %(self.remoteSocket[0], self.remoteSocket[1]))


        ##Opcode 5 [ error ]
        ##
        ##          2 bytes  2 bytes        string    1 byte
        ##          ----------------------------------------
        ##   ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
        ##          ----------------------------------------


        elif Opcode == 5:

            errCode = struct.unpack('!H',data[2:4])[0]
            errString = data[4:-1]
            self.clear('Received error code %s:%s Session closed.(%s:%s)' \
                       %(str(errCode), errString, self.remoteSocket[0],
                         self.remoteSocket[1]))


        ##
        ##Unknown Opcode
        ##

        else:
            serverLocalSocket.sendto(errUnknown, self.remoteSocket)
            self.clear('Unknown error. Session closed.(%s:%s)' \
                       %(self.remoteSocket[0], self.remoteSocket[1]))


    def reSend(self):
        serverLocalSocket.sendto(self.sendPacket, self.remoteSocket)

    def clear(self, message):
        try:
            self.sendFile.close()
        except:
            pass
        try:
            self.rcvFile.close()
        except:
            pass

        del remoteDict[self.remoteSocket]
        self.watchdog.stop()
        print(message.strip())


class Client:
    def __init__(self, serverIP, clientDir, fileName):
        self.serverIP = serverIP
        self.filePath = os.path.join(clientDir, fileName)
        self.fileName = fileName

        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.clientSocket.settimeout(5)

    def get(self):

        if os.path.isfile(self.filePath):
            print(self.fileName + ' is alredy exist. Can not start.')
            return None

        ##Opcode 1 [ Read request ]
        ##
        ##          2 bytes    string   1 byte     string   1 byte
        ##          -----------------------------------------------
        ##   RRQ   |  01   |  Filename  |   0  |    Mode    |   0  |
        ##          -----------------------------------------------

        format = '!H' + str(len(self.fileName)) + 'sB5sB'
        self.sendPacket = struct.pack(format.encode(), 1, \
                          self.fileName.encode(), 0, b'octet', 0)
        self.clientSocket.sendto(self.sendPacket, (self.serverIP, 69))

        try:
            getFile = open(self.filePath, 'wb')
        except:
            print(self.fileName + ' can not open.')
            return None

        totalDatalen = 0
        countBlock = 1
        errCount = 0

        while True:

            while errCount < 3:
                try:
                    data, remoteSocket = self.clientSocket.recvfrom(4096)
                    Opcode = struct.unpack('!H', data[0:2])[0]
                    errCount = 0
                    break
                except:
                    self.clientSocket.sendto(self.sendPacket, (self.serverIP, 69))
                    Opcode = 'Timeout'
                    errCount += 1



            ##Opcode 3 [ Data ]
            ##
            ##          2 bytes    2 bytes       n bytes
            ##          ---------------------------------
            ##   DATA  | 03    |   Block #  |    Data    |
            ##          ---------------------------------

            if Opcode == 3:

                blockNo = struct.unpack('!H',data[2:4])[0]
                if blockNo != countBlock:
                    self.clientSocket.sendto(errBlockNo, remoteSocket)
                    print('Receive wrong block. Session closed.')
                    getFile.close()
                    break

                countBlock += 1
                if countBlock == 65536:
                    countBlock = 1

                dataPayload = data[4:]

                try:
                    getFile.write(dataPayload)
                except:
                    self.clientSocket.sendto(errFilewrite, remoteSocket)
                    print('Can not write data. Session closed.')
                    getFile.close()
                    break

                totalDatalen += len(dataPayload)
                sys.stdout.write('\rget %s :%s bytes.' \
                                 %(self.fileName, totalDatalen))

                self.sendPacket = struct.pack(b'!2H', 4, blockNo)
                self.clientSocket.sendto(self.sendPacket, remoteSocket)

                if len(dataPayload) < 512:
                    sys.stdout.write('\rget %s :%s bytes. finish.' \
                                     %(self.fileName, totalDatalen))
                    getFile.close()
                    break


            elif Opcode == 5:

                errCode = struct.unpack('!H',data[2:4])[0]
                errString = data[4:-1]
                print('Received error code %s : %s' \
                           %(str(errCode), bytes.decode(errString)))
                getFile.close()
                break


            elif Opecode == 'Timeout':
                print('Timeout. Session closed.')
                try:
                    getFile.close()
                except:
                    pass
                break


            else:

                print('Unknown error. Session closed.')
                try:
                    getFile.close()
                except:
                    pass
                break


    def put(self):

        if not os.path.isfile(self.filePath):
            print(self.fileName + ' not exist. Can not start.')
            return None

        ##Opcode 2 [ Write request ]
        ##
        ##          2 bytes    string   1 byte     string   1 byte
        ##          -----------------------------------------------
        ##   WRQ   |  02   |  Filename  |   0  |    Mode    |   0  |
        ##          -----------------------------------------------

        format = '!H' + str(len(self.fileName)) + 'sB5sB'
        WRQpacket = struct.pack(format.encode(), 2, self.fileName.encode(), 0, \
                    b'octet', 0)
        self.clientSocket.sendto(WRQpacket, (self.serverIP, 69))

        try:
            putFile = open(self.filePath, 'rb')
        except:
            print(self.fileName + ' can not open.')
            return None

        endFlag = False
        totalDatalen = 0
        countBlock = 0

        while True:

            data, remoteSocket = self.clientSocket.recvfrom(4096)
            Opcode = struct.unpack('!H', data[0:2])[0]

            ##Opcode 4 [ ack ]
            ##
            ##          2 bytes    2 bytes
            ##          --------------------
            ##   ACK   | 04    |   Block #  |
            ##          --------------------

            if Opcode == 4:

                if endFlag == True:
                    putFile.close()
                    sys.stdout.write('\rput %s :%s bytes. finish.' \
                                     %(self.fileName, totalDatalen))
                    break

                blockNo = struct.unpack('!H',data[2:4])[0]

                if blockNo != countBlock:
                    self.clientSocket.sendto(errBlockNo, remoteSocket)
                    print('Receive wrong block. Session closed.')
                    putFile.close()
                    break

                blockNo += 1
                if blockNo == 65536:
                    blockNo = 0

                dataChunk = putFile.read(512)

                DATApacket = struct.pack(b'!2H', 3, blockNo) + dataChunk
                self.clientSocket.sendto(DATApacket, remoteSocket)

                totalDatalen += len(dataChunk)
                sys.stdout.write('\rput %s :%s bytes.' \
                                 %(self.fileName, totalDatalen))

                countBlock += 1
                if countBlock == 65536:
                    countBlock = 0

                if len(dataChunk) < 512:
                    endFlag = True


            elif Opcode == 5:

                errCode = struct.unpack('!H',data[2:4])[0]
                errString = data[4:-1]
                print('Receive error code %s : %s' \
                           %(str(errCode), bytes.decode(errString)))
                putFile.close()
                break


            else:

                self.clear('Unknown error. Session closed.')
                try:
                    putFile.close()
                except:
                    pass
                break



"""
Error Codes

 Value Meaning

 0 Not defined, see error message (if any).
 1 File not found.
 2 Access violation.
 3 Disk full or allocation exceeded.
 4 Illegal TFTP operation.
 5 Unknown transfer ID.
 6 File already exists.
"""

errNofile = struct.pack(b'!2H15sB', 5, 1, b'File not found.', 0)
errFileopen = struct.pack(b'!2H18sB', 5, 2, b'Can not open file.', 0)
errFilewrite = struct.pack(b'!2H19sB', 5, 2, b'Can not write file.', 0)
errBlockNo = struct.pack(b'!2H20sB', 5, 5, b'Unknown transfer ID.', 0)
errFileExists = struct.pack(b'!2H20sB', 5, 6, b'File already exists.', 0)
errUnknown = struct.pack(b'!2H23sB', 5, 4, b'Illegal TFTP operation.', 0)


def test():
    '''
    server runnning
        Usage: python -m minimumTFTP -s [directory]

    client get
        Usage: python -m minimumTFTP -g [serverIP] [directory] [filename]

    client put
        Usage: python -m minimumTFTP -p [serverIP] [directory] [filename]
    '''

    if '-s' in sys.argv:
        try:
            Server(sys.argv[2]).run()
        except:
            print(sys.exc_info()[0])
            raise

    elif '-g' in sys.argv:
        try:
            Client(sys.argv[2], sys.argv[3], sys.argv[4]).get()
        except:
            print(sys.exc_info()[0])
            raise

    elif '-p' in sys.argv:
        try:
            Client(sys.argv[2], sys.argv[3], sys.argv[4]).put()
        except:
            print(sys.exc_info()[0])
            raise

    elif 'help' in sys.argv:
        print(test.__doc__)
        sys.exit(0)

    else:
        print(test.__doc__)
        sys.exit(0)

if __name__ == '__main__':
    test()

