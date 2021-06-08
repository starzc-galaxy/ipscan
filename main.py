# -*- coding: utf-8 -*-
"""一个内网在线ip扫描工具 可以让其断网"""
__author__ = "zc"

import  sys
from PyQt5.QtWidgets import QApplication

from scanwidget import IpScan

if __name__ == '__main__':
    app = QApplication(sys.argv)
    scanwidget = IpScan()
    scanwidget.show()
    sys.exit(app.exec_())