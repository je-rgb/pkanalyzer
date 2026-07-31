TS_PACKET_SIZE = 188

def analyze_ts(file_path):
    print("=== TS Analyzer ===")

    try:
        f= open(file_path, "rb")
    except FileNotFoundError:
        print(f"Error: File을 찾을 수 없습니다. '{file_path}'")
        return None
    except PermissionError:
        print(f"Error: 파일에 접근할 수 없습니다. '{file_path}'")
        return None
    except OSError as e:
        print(f"Error: 파일을 열 수 없습니다. '{file_path}' - {e}")
        return None

    with f:

        count = 0
        
        pcr_pid = None
        pmt_pid = None
        last_cc ={}
        valid_pids ={0, 17}
        pmt_parsed = False

        pid_count ={}

        sync_error_count = 0
        cc_error_count = 0
        unknown_pid_count = 0

        video_pid = None
        audio_pid = None

        video_codec = None
        audio_codec = None

        packets =[]

        while True:

            try: 
                packet = f.read(TS_PACKET_SIZE)
            except OSError as e:
                print(f"Error reading packet: {e}")
                break

            if len(packet) < TS_PACKET_SIZE:
                if len(packet) >0:
                    print(f"Warning: 파일 끝에 불완전한 패킷이 있습니다 (길이: {len(packet)} 바이트).")
                break

            count += 1

            try:
                # Sync Byte Check
                sync_byte = packet[0]

                if sync_byte != 0x47:
                    sync_error_count += 1
                    print(f"[SYNC LOSS] Packet {count}: Sync Byte = 0x{sync_byte:02X} (Expected: 0x47)")
                    break

                # Header Parsing
                tei = (packet[1] & 0x80) >> 7
                pusi = (packet[1] & 0x40) >> 6
                pri = (packet[1] & 0x20) >> 5

                pid = ((packet[1] & 0x1F) << 8) | packet[2]

                # PID별 패킷 개수
                if pid in pid_count:
                    pid_count[pid] += 1
                else:
                    pid_count[pid] = 1

                scrambling_control = (packet[3] & 0xC0) >> 6
                afc = (packet[3] & 0x30) >> 4
                cc = packet[3] & 0x0F

                # CC 유효성 검사
                if pid in last_cc:

                    expected_cc = (last_cc[pid] + 1) % 16

                    if cc != expected_cc:
                        cc_error_count += 1
                        print(f"CC Error: PID {pid}: " 
                                f"Expected {expected_cc}, Received {cc}")

                last_cc[pid] = cc

                # Payload 시작 위치
                payload_start = 4

                # Adaptation Field가 있는 경우
                if afc == 3:
                    adaptation_length = packet[4]
                    payload_start = 5 + adaptation_length


                packets.append({
                    "no": count,
                    "pid": pid,
                    "tei": tei,
                    "pusi": pusi,
                    "pri": pri,
                    "scrambling_control": scrambling_control,
                    "afc": afc,
                    "cc": cc,
                    "sync_byte": sync_byte

                })


                # PAT Packet 확인
                if pid == 0 and pusi == 1:
                    try:
                        print("\n===== PAT Packet 발견 =====")

                        # Pointer Field
                        pointer_field = packet[payload_start]
                        pat_start = payload_start + 1 + pointer_field

                        # Table ID
                        table_id = packet[pat_start]

                        print(f"Pointer Field : {pointer_field}")
                        print(f"Table ID      : 0x{table_id:02X}")

                        # PAT Table 확인
                        if table_id == 0x00:

                            section_length = (
                                ((packet[pat_start + 1] & 0x0F) << 8)
                                | packet[pat_start + 2]
                            )

                            program_number = (packet[pat_start + 8] << 8) | packet[pat_start + 9]

                            print(f"Section Length : {section_length}")
                            print(f"Program Number : {program_number}")

                            # PMT PID 확인
                            pmt_pid = ((packet[pat_start + 10] & 0x1F) << 8) | packet[pat_start + 11]
                            valid_pids.add(pmt_pid)
                            print(f"PMT PID        : {pmt_pid}")

                    except IndexError as e:
                        parse_error_count += 1
                        print(f"Error: PAT 파싱 중 오류 발생 (범위초과) : {e}")

                # PMT Packet 확인
                if pmt_pid is not None and pid == pmt_pid:

                    try:
                        print("\n===== PMT Packet 발견 =====")

                        # Pointer Field
                        pointer_field = packet[payload_start]
                        pmt_start = payload_start + 1 + pointer_field


                        # Table ID 확인
                        table_id = packet[pmt_start]
                        print(f"Table ID : 0x{table_id:02X}")

                        # PCR PID 확인
                        pcr_pid = (
                        ((packet[pmt_start + 8] & 0x1F) << 8)
                        | packet[pmt_start + 9]
                    )

                        print(f"PCR PID : {pcr_pid}")

                        # Program Info Length 확인
                        program_info_length = (
                            ((packet[pmt_start + 10] & 0x0F) << 8)
                        | packet[pmt_start + 11]
                        )

                        print(f"Program Info Length : {program_info_length}")

                        # Section Length 확인
                        section_length = (
                            ((packet[pmt_start + 1] & 0x0F) << 8)
                            | packet[pmt_start + 2]
                        )
                        section_end = pmt_start + 3 + section_length - 4  # CRC 제외

                        # Stream 읽기
                        stream_start = pmt_start + 12 + program_info_length

                        while stream_start < section_end:

                            stream_type = packet[stream_start]

                            elementary_pid = (
                                ((packet[stream_start + 1] & 0x1F) << 8)
                                | packet[stream_start + 2]
                            )

                            valid_pids.add(elementary_pid)

                            es_info_length = (
                                ((packet[stream_start + 3] & 0x0F) << 8)
                                | packet[stream_start + 4]
                            )

                            if stream_type == 0x02:
                                codec = "MPEG-2 Video"
                                video_pid = elementary_pid
                                video_codec = codec
                            elif stream_type == 0x1B:
                                codec = "H.264 Video"
                                video_pid = elementary_pid
                                video_codec = codec
                            elif stream_type == 0x24:
                                codec = "H.265 Video"
                                video_pid = elementary_pid
                                video_codec = codec
                            elif stream_type == 0x0F:
                                codec = "AAC Audio"
                                audio_pid = elementary_pid
                                audio_codec = codec
                            elif stream_type == 0x03:
                                codec = "MPEG Audio"
                                audio_pid = elementary_pid
                                audio_codec = codec
                            else:
                                codec = "Unknown"

                            print(f"Codec : {codec}")

                            print(f"Stream Type : 0x{stream_type:02X}")
                            print(f"Elementary PID : {elementary_pid}")
                            print(f"ES Info Length : {es_info_length}")
                            print()

                            # 다음 스트림으로 이동
                            stream_start += 5 + es_info_length

                        #PMT 분석완료
                        pmt_parsed = True

                        # Unknown PID 검사
                        if pmt_parsed and pid not in valid_pids:
                            print(f"[Unknown PID] Packet {count}: PID = {pid}")
                            unknown_pid_count += 1

                    except IndexError as e:
                        parse_error_count += 1
                        print(f"Error: PMT 파싱 중 오류 발생 (범위초과) : {e}") 

            except Exception as e:
                parse_error_count += 1
                print(f"Error: 패킷 파싱 중 오류 발생 : {e}")
                continue    


    return {
        "total_packets": count,
        "pmt_pid": pmt_pid,
        "pcr_pid": pcr_pid,
        "video_pid": video_pid,
        "audio_pid": audio_pid,
        "video_codec": video_codec,
        "audio_codec": audio_codec,
        "sync_error_count": sync_error_count,
        "cc_error_count": cc_error_count,
        "unknown_pid_count": unknown_pid_count,
        "pid_count": pid_count,
        "packets": packets
}
