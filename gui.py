from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QPushButton,
    QFileDialog,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
    QTabWidget,
)

from PySide6.QtGui import QColor
from analyzer import analyze_ts


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("TS Analyzer")
        self.resize(1000, 750)
        self.button = QPushButton("파일선택")
        self.table = QTableWidget()
        self.pid_table = QTableWidget()
        self.media_table = QTableWidget()
        self.info = QLabel("분석 결과가 여기에 표시됩니다.")
        self.sync_table = QTableWidget()
        self.unknown_pid_table = QTableWidget()

        self.tabs = QTabWidget()

        packet_tab = QWidget()
        packet_layout = QVBoxLayout()
        packet_layout.addWidget(QLabel("패킷 목록"))
        packet_layout.addWidget(self.table)
        packet_tab.setLayout(packet_layout)

        pid_tab = QWidget()
        pid_layout = QVBoxLayout()
        pid_layout.addWidget(QLabel("PID 통계"))
        pid_layout.addWidget(self.pid_table)
        pid_tab.setLayout(pid_layout)

        media_tab = QWidget()
        media_layout = QVBoxLayout()
        media_layout.addWidget(QLabel("미디어 스트림 정보 (PID / 프로그램 / 코덱 / 언어)"))
        media_layout.addWidget(self.media_table)
        media_tab.setLayout(media_layout)

        sync_tab = QWidget()
        sync_layout = QVBoxLayout()
        sync_layout.addWidget(QLabel("Sync Error"))
        sync_layout.addWidget(self.sync_table)
        sync_tab.setLayout(sync_layout)

        unknown_pid_tab = QWidget()
        unknown_pid_layout = QVBoxLayout()
        unknown_pid_layout.addWidget(QLabel("PMT에 정의되지 않은 PID 목록"))
        unknown_pid_layout.addWidget(self.unknown_pid_table)
        unknown_pid_tab.setLayout(unknown_pid_layout)

        self.tabs.addTab(packet_tab, "패킷 목록")
        self.tabs.addTab(pid_tab, "PID 통계")
        self.tabs.addTab(media_tab, "미디어 스트림 정보")
        self.tabs.addTab(sync_tab, "Sync Loss")
        self.tabs.addTab(unknown_pid_tab, "Unknown PID")

        layout = QVBoxLayout()
        layout.addWidget(self.button)
        layout.addWidget(self.tabs)
        layout.addWidget(self.info)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.button.clicked.connect(self.open_file)

    def open_file(self):

        file_name, _ = QFileDialog.getOpenFileName(self, "TS 파일 선택", "", "TS Files (*.ts)")

        if not file_name:
            return

        result = analyze_ts(file_name)

        if result is None:
            # analyzer.py 쪽에서 파일 열기 실패 등으로 None을 반환한 경우
            self.info.setText("분석에 실패했습니다. 파일을 열 수 없거나 접근 권한이 없습니다.")
            self.table.setRowCount(0)
            self.pid_table.setRowCount(0)
            self.media_table.setRowCount(0)
            self.sync_table.setRowCount(0)
            self.unknown_pid_table.setRowCount(0)
            return

        self.show_packets(result)
        self.show_media_pids(result)
        self.show_sync_loss(result)
        self.show_unknown_pids(result)
        self.show_summary(result)

    def show_packets(self, result):

        packets = result["packets"]

        self.table.setRowCount(len(packets))
        self.table.setColumnCount(6)

        self.table.setHorizontalHeaderLabels([
            "No",
            "PID",
            "PUSI",
            "AFC",
            "CC",
            "CC Check"
        ])

        error_color = QColor(255, 0, 0)  # 연한 빨강 - CC 오류 행

        for row, packet in enumerate(packets):

            has_error = packet.get("cc_error", False)

            no_item = QTableWidgetItem(str(packet["no"]))
            pid_item = QTableWidgetItem(str(packet["pid"]))
            pusi_item = QTableWidgetItem(str(packet["pusi"]))
            afc_item = QTableWidgetItem(str(packet["afc"]))
            cc_item = QTableWidgetItem(str(packet["cc"]))
            cc_check_item = QTableWidgetItem("오류" if has_error else "정상")


            self.table.setItem(row, 0, no_item)
            self.table.setItem(row, 1, pid_item)
            self.table.setItem(row, 2, pusi_item)
            self.table.setItem(row, 3, afc_item)
            self.table.setItem(row, 4, cc_item)
            self.table.setItem(row, 5, cc_check_item)

            if has_error:
                for item in (no_item, pid_item, pusi_item, afc_item, cc_item, cc_check_item):       
                    item.setBackground(error_color)

        pid_count = result["pid_count"]

        self.pid_table.setColumnCount(3)

        self.pid_table.setHorizontalHeaderLabels([
            "PID",
            "Packet Count",
            "Ratio(%)"
        ])

        self.pid_table.setRowCount(len(pid_count))

        for row, (pid, count) in enumerate(pid_count.items()):
            ratio = (count / result["total_packets"]) * 100
            self.pid_table.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.pid_table.setItem(row, 1, QTableWidgetItem(str(count)))
            self.pid_table.setItem(row, 2, QTableWidgetItem(f"{ratio:.2f}"))

    def show_media_pids(self, result):
        """analyzer.py에서 새로 추가된 pid_map(PID 매핑/코덱/언어 정보)을 표로 표시"""

        pid_map = result.get("pid_map", {})

        self.media_table.setColumnCount(6)
        self.media_table.setHorizontalHeaderLabels([
            "PID",
            "Program No",
            "Stream Type",
            "Codec",
            "Media Type",
            "Language",
        ])

        self.media_table.setRowCount(len(pid_map))

        for row, (pid, info) in enumerate(sorted(pid_map.items())):
            self.media_table.setItem(row, 0, QTableWidgetItem(str(pid)))
            self.media_table.setItem(row, 1, QTableWidgetItem(str(info.get("program_number"))))
            self.media_table.setItem(row, 2, QTableWidgetItem(info.get("stream_type", "-")))
            self.media_table.setItem(row, 3, QTableWidgetItem(info.get("codec", "-")))
            self.media_table.setItem(row, 4, QTableWidgetItem(info.get("media_type", "-")))
            self.media_table.setItem(row, 5, QTableWidgetItem(info.get("language") or "-"))

    def show_sync_loss(self, result):
        """analyzer.py의 sync_loss_events(재동기화 손실 이벤트)를 표로 표시"""

        events = result.get("sync_loss_events", [])

        self.sync_table.setColumnCount(4)
        self.sync_table.setHorizontalHeaderLabels([
            "시작 Packet",
            "종료 Packet",
            "시작 Offset(byte)",
            "건너뛴 바이트 수"
        ])

        self.sync_table.setRowCount(len(events))

        warn_color = QColor(255, 235, 205)  # 연한 주황색 - Sync Loss 이벤트 행

        for row, ev in enumerate(events):
            start_item = QTableWidgetItem(str(ev.get("start_packet","-")))
            end_item = QTableWidgetItem(str(ev.get("end_packet","EOF")))
            offset_item = QTableWidgetItem(str(ev.get("start_offset","-")))
            skipped_item = QTableWidgetItem(str(ev.get("skipped_bytes","-")))

            self.sync_table.setItem(row, 0, start_item)
            self.sync_table.setItem(row, 1, end_item)
            self.sync_table.setItem(row, 2, offset_item)
            self.sync_table.setItem(row, 3, skipped_item)

            for item in (start_item, end_item, offset_item, skipped_item):
                item.setBackground(warn_color)

    def show_unknown_pids(self, result):
        """analyzer.py의 unknown_pids(정의되지 않은 PID 목록)를 표로 표시"""

        summary = result.get("summary", {})

        self.unknown_pid_table.setColumnCount(3)
        self.unknown_pid_table.setHorizontalHeaderLabels([
            "PID",
            "PID (Hex)",
            "발생 횟수"
        ])

        sorted_items = sorted(summary.items(), key=lambda x: -x[1])  # PID 기준으로 정렬

        self.unknown_pid_table.setRowCount(len(sorted_items))

        alert_color = QColor(255, 205, 205)  # 연한 주황색 - Unknown PID 행
        for row, (pid, cnt) in enumerate(sorted_items):
            pid_item = QTableWidgetItem(str(pid))
            hex_item = QTableWidgetItem(f"0x{pid:04X}")
            cnt_item = QTableWidgetItem(str(cnt))

            self.unknown_pid_table.setItem(row, 0, pid_item)
            self.unknown_pid_table.setItem(row, 1, hex_item)
            self.unknown_pid_table.setItem(row, 2, cnt_item)

            for item in (pid_item, hex_item, cnt_item):
                item.setBackground(alert_color)


    def show_summary(self, result):

        programs = result.get("programs", {})
        if programs:
            program_lines = "\n        ".join(
                f"Program {num} -> PMT PID {pid}" for num, pid in programs.items()
            )
        else:
            program_lines = "없음"

        network_pid = result.get("network_pid")
        sync_loss_events = result.get("sync_loss_events", [])

        self.info.setText(
            f"""
        총 패킷 : {result["total_packets"]}

        표시된 패킷: {len(result['packets'])}
        
        (성능을 위해 처음 1000개 패킷만 표시됩니다.)

        프로그램 :
        {program_lines}

        Network PID : {network_pid if network_pid is not None else "-"}

        Video Codec : {result["video_codec"]}

        Audio Codec : {result["audio_codec"]}

        Sync Error : {result["sync_error_count"]} (재동기화 구간 {len(sync_loss_events)}개, 상세는 'Sync Loss' 탭 참고)
        
        CC Error : {result["cc_error_count"]} (오류 패킷은 '패킷 목록' 탭에서 빨간색으로 표시됨)

        Unknown PID Error : {result["unknown_pid_count"]} (상세는 'Unknown PID' 탭 참고)

        Parse Error : {result["parse_error_count"]}
        """
        )