import sys
import os
import socket
from PyQt5 import QtCore, QtWidgets

class UDPWorker(QtCore.QObject):
    dataChanged = QtCore.pyqtSignal(str)

    def __init__(self, parent=None):
        super(UDPWorker, self).__init__(parent)
        self.server_start = False

    @QtCore.pyqtSlot()
    def start(self):
        self.dataChanged.emit("UDP listen started:")
        self.server_start = True
        ip = "0.0.0.0"
        port = 14700
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip,port))
        self.process()

    def process(self):
        while self.server_start:
            data, addr = self.sock.recvfrom(1024)
            self.dataChanged.emit(str(data))

class UDPWidget(QtWidgets.QWidget):
    started = QtCore.pyqtSignal()
    serverAddressPort = ("192.168.0.108", 14551)
    UDPTxSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    bytesToSend = bytearray()
    bytesToSend.append(0x73)
    bytesToSend.append(0x06)
    bytesToSend.append(0x01)
    bytesToSend.append(0x02)
    bytesToSend.append(0x03)
    bytesToSend.append(0x04)
    bytesToSend.append(0x05)
    bytesToSend.append(0x06)
    bytesToSend.append(0x15)

    def send_process(self):
        self.UDPTxSocket.sendto(self.bytesToSend, self.serverAddressPort)

    def int_to_inv_bytearray(self, int_value):
        input_bytearray = bytearray()
        my_0 = int_value & 0x000000FF
        my_1 = (int_value & 0x0000FF00) >> 8
        my_2 = (int_value & 0x00FF0000) >> 16
        my_3 = (int_value & 0xFF000000) >> 24
        input_bytearray.append(my_0)
        input_bytearray.append(my_1)
        input_bytearray.append(my_2)
        input_bytearray.append(my_3)
        return input_bytearray

    def __init__(self, parent=None):
        super(UDPWidget, self).__init__(parent)
        btn = QtWidgets.QPushButton("Reseive Start")
        btn.clicked.connect(self.started)
        self.lst = QtWidgets.QListWidget()
        btn_send = QtWidgets.QPushButton("Send Me")
        btn_send.clicked.connect(self.send_process)

        lay = QtWidgets.QVBoxLayout(self)
        lbUdpReceive = QtWidgets.QLabel("udp receiver")
        lay.addWidget(lbUdpReceive)
        lay.addWidget(btn)
        lay.addWidget(btn_send)
        lay.addWidget(self.lst)

        self.setWindowTitle("udp receive")

    @QtCore.pyqtSlot(str)
    def addItem(self, text):
        self.lst.insertItem(0, text)

if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    w = UDPWidget()
    worker = UDPWorker()
    thread = QtCore.QThread()
    thread.start()
    worker.moveToThread(thread)
    w.started.connect(worker.start)
    worker.dataChanged.connect(w.addItem)
    w.show()
    sys.exit(app.exec_())

