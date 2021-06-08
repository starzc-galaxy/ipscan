import datetime
from PyQt5.QtWidgets import QWidget,QAbstractItemView,QTableView,QHeaderView,QCheckBox,QTableWidgetItem,QApplication
from PyQt5.QtCore import Qt
from ipscan import Ui_Form
from task import Scan,IPNET,Arpattack

class IpScan():
    """主窗口类"""
    def __init__(self):
        self.w = QWidget()
        self.ipsacn = Ui_Form()
        self.ipsacn.setupUi(self.w)
        self.initUI()
        self.choose = set() #勾选框
        self.arpthread = None

    def initUI(self):
        """二次修改Ui界面设置"""
        #设置按钮连接
        self.ipsacn.pushButton.clicked.connect(self.scan)
        self.ipsacn.pushButton_2.clicked.connect(self.downip)
        #设置table widget
        self.ipsacn.tableWidget.setSelectionMode(QAbstractItemView.SingleSelection|QHeaderView.Stretch)  # 设置只能选中一行
        self.ipsacn.tableWidget.setEditTriggers(QTableView.NoEditTriggers)  # 不可编辑
        self.ipsacn.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)  # 设置只有行选中
        self.ipsacn.tableWidget.horizontalHeader().setStretchLastSection(True)#设置最后一列拉伸至最大
        self.ipsacn.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ipsacn.tableWidget.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)

    def show(self):
        self.w.show()

    def scan(self):
        #先清除
        for rowNum in range(0, self.ipsacn.tableWidget.rowCount())[::-1]:  # 逆序删除，正序删除会有一些删除不成功
            self.ipsacn.tableWidget.removeRow(rowNum)
        self.scanthread = Scan(IPNET)
        self.scanthread._signal.connect(self.adddata)
        self.scanthread.start()

    def downip(self):
        if self.arpthread:
            print(self.arpthread)
            self.text_browser("攻击停止")
            self.arpthread.stop()
            self.arpthread = None
        else:
            self.arpthread = Arpattack(self.getlist())
            self.arpthread._signal.connect(self.text_browser)
            self.arpthread.start()

    def getlist(self):
        data = []
        for i in self.choose:
            if i.isChecked():
                data.append((i.mac,i.ip))
        return data

    def adddata(self,data):
        self.text_browser("发现主机: {}".format(data))
        mac , ip = data.split("---")
        num = self.ipsacn.tableWidget.rowCount()
        self.ipsacn.tableWidget.setRowCount(num + 1)
        ck = QCheckBox()
        ck.ip = ip
        ck.mac = mac
        ck.setStyleSheet("QCheckBox{margin:13px};")
        self.ipsacn.tableWidget.setCellWidget(num, 0, ck)
        self.choose.add(ck)
        taitem = QTableWidgetItem(ip)
        taitem.setTextAlignment(Qt.AlignCenter)
        self.ipsacn.tableWidget.setItem(num, 1, taitem)
        taitem = QTableWidgetItem(mac)
        taitem.setTextAlignment(Qt.AlignCenter)
        self.ipsacn.tableWidget.setItem(num, 2, taitem)

    def text_browser(self, line):
        # mypstr = datetime.datetime.now().strftime('%c') + "{}".format(line)
        self.ipsacn.textBrowser.append(line)
        self.Bcursor = self.ipsacn.textBrowser.textCursor()
        self.ipsacn.textBrowser.moveCursor(self.Bcursor.End)  # 光标移到最后，这样就会自动显示出来
        QApplication.processEvents()
