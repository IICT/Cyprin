import sys
from PySide import QtCore, QtGui
from Qt.ui import Ui_MainWindow as MainView
import Sniffer


# ========================================================================================================
# Main program
# ========================================================================================================

class MainWindow(QtGui.QMainWindow):
    def __init__(self, app, parent=None):
        super(MainWindow, self).__init__(parent)
        self.__view = MainView()
        self.__view.setupUi(self)
        emtpyPacketList = []
        self.__view.tableView.setModel(PacketList(self, emtpyPacketList))
        self.__view.tableView.resizeColumnsToContents()
        self.__view.startButton.clicked.connect(self.startCapture)
        self.__view.ipAddress.textChanged.connect(lambda : self.checkField(self.__view.ipAddress, Sniffer.CheckIP))
        self.__view.protocol.textChanged.connect(lambda : self.checkField(self.__view.protocol, Sniffer.CheckTransportProtocol))
        self.__view.port.textChanged.connect(lambda : self.checkField(self.__view.port, Sniffer.CheckPort))
        #font = self.__view.tableView.horizontalHeader().font()
        #font.setBold(True)
        #self.__view.tableView.horizontalHeader().setFont(font)
        v = self.__view.tableView.verticalHeader()
        v.setDefaultSectionSize(v.fontMetrics().height()+15)
        self.__view.tableView.resizeColumnsToContents()
        self.__view.tableView.horizontalHeader().setStretchLastSection(True)

    def checkField(self, lineEdit, check):
        content = lineEdit.text().strip()
        if not content:
            lineEdit.setStyleSheet("QLineEdit{background: white;}")
        elif not check(content):
            lineEdit.setStyleSheet("QLineEdit{background: pink;}")
        else:
            lineEdit.setStyleSheet("QLineEdit{background: lightgreen;}")

    def handleRowSelection(self, selected, deselected):
        selectedRows = self.__view.tableView.selectionModel().selectedRows()
        if selectedRows != []:
            row = selectedRows[0]
            payload = row.sibling(row.row(),7).data()
            self.__view.payload.clear()
            self.__view.payload.insertPlainText(payload)

    def enterGuiCaptureMode(self):
        self.__view.startButton.setEnables = False
        buttonText = self.__view.startButton.text()
        self.__view.startButton.setText("Capture en cours...")
        self.__view.tableView.setModel(PacketList(self, []))
        self.__view.payload.clear()
        QtCore.QCoreApplication.processEvents()
        return buttonText

    def leaveGuiCaptureMode(self, buttonText):
        self.__view.tableView.resizeColumnsToContents()
        self.__view.tableView.horizontalHeader().setStretchLastSection(True)
        selection = self.__view.tableView.selectionModel()
        selection.selectionChanged.connect(self.handleRowSelection)
        self.__view.startButton.setText(buttonText)
        self.__view.startButton.setEnables = True
        QtCore.QCoreApplication.processEvents()

    def checkFilters(self, ipAddress, protocol, port):
        return ( (not ipAddress or Sniffer.CheckIP(ipAddress)) and
                 (not protocol or Sniffer.CheckTransportProtocol(protocol)) and
                 (not port or Sniffer.CheckPort(port)) )

    def startCapture(self):
        numPackets = self.__view.numPackets.value()
        ipAddress = self.__view.ipAddress.text().strip()
        protocol = self.__view.protocol.text().strip()
        port = self.__view.port.text().strip()

        if not self.checkFilters(ipAddress, protocol, port):
            return

        buttonText = self.enterGuiCaptureMode()
        try:
            filter = Sniffer.MakeFilter(ipAddress=ipAddress, transportProtocol=protocol, port=port)
            packets = Sniffer.Capture(count=numPackets, filter=filter, timeout=60)
            self.__view.tableView.setModel(PacketList(self, packets))
        except ValueError, message:
                print message
        finally:
            self.leaveGuiCaptureMode(buttonText)


class PacketList(QtCore.QAbstractTableModel):
    header = ['MAC src', 'MAC dst', 'IP src', 'IP dst', 'Proto', 'Port src', 'Port dst', 'Contenu']

    def __init__(self, parent, myList, *args):
        QtCore.QAbstractTableModel.__init__(self, parent, *args)
        self.myList = myList

    def rowCount(self, parent):
        return len(self.myList)

    def columnCount(self, parent):
        return len(self.header)

    def data(self, index, role):
        if not index.isValid():
            return None
        elif role != QtCore.Qt.DisplayRole:
            return None
        return " " + str(self.myList[index.row()].flat()[index.column()]) + " "

    def headerData(self, section, orientation, role):
        if role != QtCore.Qt.DisplayRole:
            return None
        if orientation == QtCore.Qt.Horizontal:
            return self.header[section]
        elif orientation == QtCore.Qt.Vertical:
            return section+1
        else:
            return None


if __name__ == "__main__":
    qtApp = QtGui.QApplication(sys.argv)
    win = MainWindow(qtApp)
    win.resize(1600,1200)
    win.show()
    sys.exit(qtApp.exec_())
