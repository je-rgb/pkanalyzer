from PySide6.QtWidgets import(
    QMainWindow,
    QWidget,
    QPushButton,
    QFileDialog,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
)

from analyzer import analyze_ts

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("TS Analyzer")
        self.resize(900, 600)
        self.button = QPushButton("파일선택")
        self.table = QTableWidget()
        self.info = QLabel("분석 결과가 여기에 표시됩니다.")

        layout = QVBoxLayout()
        layout.addWidget(self.button)
        layout.addWidget(self.table)
        layout.addWidget(self.info)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.button.clicked.connect(self.open_file)


    def open_file(self):

        file_name, _ = QFileDialog.getOpenFileName(self, "TS 파일 선택", "", "TS Files (*.ts)")

        if file_name:
            result = analyze_ts(file_name)
            self.show_packets(result)

    def show_packets(self, result):

        packets = result["packets"]

        self.table.setRowCount(len(packets))
        self.table.setColumnCount(5)

        self.table.setHorizontalHeaderLabels([
            "No",
            "PID",
            "PUSI",
            "AFC",
            "CC"
        ])

        for row, packet in enumerate(packets):

            self.table.setItem(row, 0, QTableWidgetItem(str(packet["no"])))
            self.table.setItem(row, 1, QTableWidgetItem(str(packet["pid"])))
            self.table.setItem(row, 2, QTableWidgetItem(str(packet["pusi"])))
            self.table.setItem(row, 3, QTableWidgetItem(str(packet["afc"])))
            self.table.setItem(row, 4, QTableWidgetItem(str(packet["cc"])))

        self.info.setText(
            f"""총 패킷 : {result["total_packets"]}

        Video Codec : {result["video_codec"]}

        Audio Codec : {result["audio_codec"]}

        Sync Error : {result["sync_error_count"]}

        CC Error : {result["cc_error_count"]}
        """
        )

        
