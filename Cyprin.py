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
        #font = self.__view.tableView.horizontalHeader().font()
        #font.setBold(True)
        #self.__view.tableView.horizontalHeader().setFont(font)
        v = self.__view.tableView.verticalHeader()
        v.setDefaultSectionSize(v.fontMetrics().height()+15)
        self.__view.tableView.resizeColumnsToContents()
        self.__view.tableView.horizontalHeader().setStretchLastSection(True)

    def handleRowSelection(self, selected, deselected):
        selectedRows = self.__view.tableView.selectionModel().selectedRows()
        if selectedRows != []:
            row = selectedRows[0]
            payload = row.sibling(row.row(),7).data()
            self.__view.payLoad.clear()
            self.__view.payLoad.insertPlainText(payload)

    def startCapture(self):
        self.__view.startButton.setEnables = False
        buttonText = self.__view.startButton.text()
        self.__view.startButton.setText("Capture en cours...")
        self.__view.tableView.setModel(PacketList(self, []))
        self.__view.payLoad.clear()
        QtCore.QCoreApplication.processEvents()
 
        numPackets = self.__view.numPackets.value()
        ipAddress = self.__view.ipAddress.text()
        protocol = self.__view.protocol.text()
        port = self.__view.port.text()
        try:
            filter = Sniffer.MakeFilter(ipAddress=ipAddress, transportProtocol=protocol, port=port)
            packets = Sniffer.Capture(count=numPackets, filter=filter, timeout=60)
            self.__view.tableView.setModel(PacketList(self, packets))
        except ValueError, message:
                print message
        finally:
            self.__view.tableView.resizeColumnsToContents()
            self.__view.tableView.horizontalHeader().setStretchLastSection(True)
            selection = self.__view.tableView.selectionModel()
            selection.selectionChanged.connect(self.handleRowSelection)
            self.__view.startButton.setText(buttonText)
            self.__view.startButton.setEnables = True


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


