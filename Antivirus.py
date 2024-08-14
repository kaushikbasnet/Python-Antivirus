import sys
from PyQt5 import QtWidgets, QtGui, QtCore
from virustotal_python import Virustotal
import hashlib
import os


class AntivirusApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Create UI elements
        self.setWindowTitle('Simple Antivirus')
        self.setGeometry(300, 300, 400, 200)

        # Set window icon
        self.setWindowIcon(QtGui.QIcon('antivirus_icon.png'))  # Make sure you have an icon file

        # Create layout
        self.layout = QtWidgets.QVBoxLayout()

        # Create title label
        self.titleLabel = QtWidgets.QLabel('Simple Antivirus')
        self.titleLabel.setFont(QtGui.QFont('Arial', 16))
        self.titleLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.layout.addWidget(self.titleLabel)

        # Create file selection button
        self.fileButton = QtWidgets.QPushButton('Choose File')
        self.fileButton.setFont(QtGui.QFont('Arial', 12))
        self.fileButton.setStyleSheet("background-color: #4CAF50; color: white;")
        self.fileButton.clicked.connect(self.openFile)
        self.layout.addWidget(self.fileButton)

        # Create result label
        self.resultLabel = QtWidgets.QLabel('')
        self.resultLabel.setFont(QtGui.QFont('Arial', 12))
        self.resultLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.layout.addWidget(self.resultLabel)

        # Set layout and window style
        self.setLayout(self.layout)
        self.setStyleSheet("background-color: #F5F5F5;")
        self.show()

    def openFile(self):
        options = QtWidgets.QFileDialog.Options()
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)', options=options)
        if filePath:
            self.scanFile(filePath)

    def scanFile(self, filePath):
        # Calculate SHA256 hash of the file
        sha256_hash = hashlib.sha256()
        with open(filePath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # Simulate checking the hash with VirusTotal
        self.resultLabel.setText(f'Scanned: {os.path.basename(filePath)}\nSHA256: {file_hash}\nStatus: Safe')


def main():
    app = QtWidgets.QApplication(sys.argv)
    ex = AntivirusApp()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
