import os
import sys  # 导入包

from PyQt5 import QtCore
from PyQt5.Qt import QWidget, QApplication
from PyQt5.QtWidgets import QFileDialog
from PyQt5.uic import loadUi

def openFile(filePath):
    try:
        f = open(filePath, 'r')
        return f
    except Exception as e:
        print(e)


def ipProcess_overFlow(p):
    while p > 0xffff:
        temp = p >> 16
        p &= 0xffff
        p += temp
    return p


def ipProcess(s):
    # 设置回传值
    ret = ""
    # 去除不要的头部
    uselessHead = s[0:28]
    # 获取头部的tag ip对应的tag是0800
    tag = uselessHead[-4:]

    # 如果不是直接回到主函数
    if tag != '0800':
        print("It's not a ip-packet, " + "it's tag is 0x" + tag + ".")
        ret = ret + "It's not a ip-packet, " + "it's tag is 0x" + tag + "."
        return ret

    # 获取输入的16进制字符流的长度
    sLen = len(s)
    # 创建tuple存储一下16进制数方便运算
    ipHead = ()

    # 将ip头部到最后全部存储到ipHead中
    for i in range(28, sLen, 4):
        temp = s[i:i + 4]
        tempInt = int(temp, 16)
        ipHead = ipHead + (tempInt,)
    # print(hex(ipHead[0]))

    ipHeadLength = ipHead[0]
    ipHeadLength &= 0xf00
    ipHeadLength >>= 8
    ipHeadLength *= 2

    ret = ret + "ip头部" +str(ipHeadLength*2) + "字节\n"


    sumExceptR = 0
    HeaderCheckSum = ipHead[5]

    ret = ret + "包中所自带的检验和为" + str(hex(HeaderCheckSum)) + "\n" + "开始验证：\n"

    ret = ret + "将ip头部的16进制全部相加，下面显示16进制的ip头部\n"

    # 将除了checkSum的其他数字全部加起来
    for i in range(0, ipHeadLength):
        sumExceptR += ipHead[i]
        ret = ret + str(hex(ipHead[i])) + "\n"

    ret = ret + "因为是一起相加的，所以检验和是置零的，减去自带的检验和,得到结果："
    sumExceptR -= HeaderCheckSum

    ret = ret + str(hex(sumExceptR)) + "\n"

    ret = ret + "计算中的进位是进位到最低位的，这里采用溢出递归的写法,得到结果:\n"
    # 相加之后处理溢出
    answer = sumExceptR
    answer = ipProcess_overFlow(answer)

    ret = ret + str(hex(answer)) + "\n" +"ip首部检验和置零得到的结果：" + "\n" + str(hex(answer)) + "\n"

    answer = answer ^ 0xffff

    ret = ret + "取反：\n" + str(hex(answer)) + "\n"
    answer += sumExceptR
    ret = ret + "和剩余部分重新累加：\n" + str(hex(answer)) + "\n" + "处理溢出,得到结果：\n"
    answer = ipProcess_overFlow(answer)
    ret = ret + str(hex(answer)) + "\n"


    # 如果最后的验证是0xffff，那么说明首部检验和正确
    if answer == 0xffff:
        print("ip数据包首部检验和正确")
        ret = ret + "ip数据包首部检验和正确\n\n"
    else:
        print("ip数据包首部检验和错误")
        ret = ret + "ip数据包首部检验和错误\n\n"


    # 获取在ip情况下所使用的8位协议
    protocol = ipHead[4] & 0xff

    ret = ret + "获取ip协议中携带的protocol协议号\n" + str(protocol) + "\n"

    # 6是tcp协议
    if protocol == 6:
        # tcp
        print("This protocol is tcp!")
        ret = ret + "是tcp协议\n\n"
        # ipHead[6] + ipHead[7] = SourceAddress
        # ipHead[8] + ipHead[9] = DestinationAddress
        ret = ret + "tcp协议的检验和要用到伪首部，伪首部的构成：\n源ip地址 + 目标ip地址 + 协议号 + tcp协议长度 \n 源ip地址（以16进制显示，只要2个16进制数）：\n"
        ret = ret + str(hex(ipHead[6])) + '\n' + str(hex(ipHead[7])) + '\n'

        ret = ret + " 目标ip地址（以16进制显示，只要2个16进制数）：\n"
        ret = ret + str(hex(ipHead[8])) + '\n' + str(hex(ipHead[9])) + '\n' + "协议号已知是6，tcp协议长度在下面计算的时候加上\n"

        # 创建伪首部
        fakeHead = 0
        fakeHead += ipHead[6] + ipHead[7]
        fakeHead += ipHead[8] + ipHead[9]
        fakeHead += protocol

        # ipHead[10] = SourcePort
        # ipHead[11] = DestinationPort

        # udpHeadStart = ipHeadLength
        # udplength = len(ipHead) - ipHeadLength
        # print(udplength)

        tcpAnswer = fakeHead

        ret = ret + "没有加上tcp长度的伪首部：\n" + str(hex(tcpAnswer)) + '\n'

        ret = ret + "tcp自带的检验依然需要先置零，处理的过程中就是都加上再减去\n 下面以16进制表示ip的头部和数据\n"

        tcpHead = ()
        for i in range(ipHeadLength, len(ipHead)):
            tcpHead = tcpHead + (ipHead[i],)
            tcpAnswer += ipHead[i]
            ret = ret + str(hex(ipHead[i])) + '\n'
        tcpAnswer += len(tcpHead)
        ret = ret + "tcp的长度单位是以2字节为单位的，长度为：\n" + str(hex(len(tcpHead))) + '\n'

        tcpAnswer -= tcpHead[3]
        ret = ret + "此时的计算值为：\n" + str(hex(tcpAnswer))

        tcpSum = tcpAnswer

        # print(hex(udpAnswer))
        tcpAnswer = ipProcess_overFlow(tcpAnswer)
        ret = ret + "处理溢出：\n" + str(hex(tcpAnswer)) + '\n'
        tcpAnswer = tcpAnswer ^ 0xffff
        ret = ret + "取反：\n" + str(hex(tcpAnswer)) + '\n'
        tcpAnswer += tcpSum
        ret = ret + "填入校验和之后再计算：\n" + str(hex(tcpAnswer)) + '\n'
        tcpAnswer = ipProcess_overFlow(tcpAnswer)
        ret = ret + "处理溢出，得到结果：\n" + str(hex(tcpAnswer)) + '\n'

        if tcpAnswer == 0xffff:
            print("ip/tcp数据包首部检验和正确")
            ret = ret + "ip/tcp数据包首部检验和正确\n"
        else:
            print("ip/tcp数据包首部检验和错误")
            ret = ret + "ip/tcp数据包首部检验和错误\n"

    # 17是udp协议
    elif protocol == 17:
        print("This protocol is udp!")
        ret = ret + "是udp协议\n\n"
        # udp

        # ipHead[6] + ipHead[7] = SourceAddress
        # ipHead[8] + ipHead[9] = DestinationAddress

        ret = ret + "udp协议的检验和要用到伪首部，伪首部的构成：\n源ip地址 + 目标ip地址 + 协议号 + udp协议长度 \n 源ip地址（以16进制显示，只要2个16进制数）：\n"
        ret = ret + str(hex(ipHead[6])) + '\n' + str(hex(ipHead[7])) + '\n'

        ret = ret + " 目标ip地址（以16进制显示，只要2个16进制数）：\n"
        ret = ret + str(hex(ipHead[8])) + '\n' + str(hex(ipHead[9])) + '\n' + "协议号已知是17，udp协议长度在下面计算的时候加上\n"

        # 创建伪首部
        fakeHead = 0
        fakeHead += ipHead[6] + ipHead[7]
        fakeHead += ipHead[8] + ipHead[9]
        fakeHead += protocol

        # ipHead[10] = SourcePort
        # ipHead[11] = DestinationPort

        # udpHeadStart = ipHeadLength
        # udplength = len(ipHead) - ipHeadLength
        # print(udplength)

        udpAnswer = fakeHead

        ret = ret + "没有加上udp长度的伪首部：\n" + str(hex(udpAnswer)) + '\n'

        ret = ret + "udp自带的检验依然需要先置零，处理的过程中就是都加上再减去\n 下面以16进制表示ip的头部和数据\n"

        udpHead = ()
        for i in range(ipHeadLength, len(ipHead)):
            udpHead = udpHead + (ipHead[i],)
            udpAnswer += ipHead[i]
            ret = ret + str(hex(ipHead[i])) + '\n'
        udpAnswer += len(udpHead)
        ret = ret + "udp的长度单位是以2字节为单位的，长度为：\n" + str(hex(len(udpHead))) + '\n'
        udpAnswer -= udpHead[3]
        ret = ret + "此时的计算值为：\n" + str(hex(udpAnswer))


        udpSum = udpAnswer

        # print(hex(udpAnswer))

        udpAnswer = ipProcess_overFlow(udpAnswer)
        ret = ret + "处理溢出：\n" + str(hex(udpAnswer)) + '\n'
        udpAnswer = udpAnswer ^ 0xffff
        ret = ret + "取反：\n" + str(hex(udpAnswer)) + '\n'
        udpAnswer += udpSum
        ret = ret + "填入校验和之后再计算：\n" + str(hex(udpAnswer)) + '\n'
        udpAnswer = ipProcess_overFlow(udpAnswer)
        ret = ret + "处理溢出，得到结果：\n" + str(hex(udpAnswer)) + '\n'

        if udpAnswer == 0xffff:
            print("ip/udp数据包首部检验和正确")
            ret = ret + "ip/udp数据包首部检验和正确\n"

        else:
            print("ip/udp数据包首部检验和错误")
            ret = ret + "ip/udp数据包首部检验和错误\n"



    # 处理其他情况
    else:
        print("There's another protocol, no tcp or udp protocol!")
        ret = ret + "不是tcp或者udp协议，是其他协议\n\n"

    return ret



QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)


class MainWindow(QWidget):

    # 加载ui
    def __init__(self):
        super(QWidget, self).__init__()
        loadUi('./ui1.ui', self)

    def printLog(self, log):
        self.screen.append("hi")

        return

    def resetScreen(self):
        self.screen.setText("")
        self.filePath.setText("")
        return

    def getFilePath(self):
        filename, filetype = QFileDialog.getOpenFileName(self, "选取文件", os.getcwd(),
                                                         "All Files (*)")
        self.filePath.setText(filename)

        f = openFile(filename)
        fileStream = f.read()
        log = ipProcess(fileStream)
        self.screen.append(log)

        return


if __name__ == "__main__":
    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
    QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
    app = QApplication(sys.argv)
    app = QApplication.instance()
    if app is None:
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        app = QApplication(sys.argv)
    Widget = MainWindow()
    Widget.show()
    sys.exit(app.exec_())
