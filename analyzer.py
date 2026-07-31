TS_PACKET_SIZE = 188

# stream_type -> (코덱명, 미디어 타입)
STREAM_TYPE_INFO = {
    0x02: ("MPEG-2 Video", "video"),
    0x1B: ("H.264 Video", "video"),
    0x24: ("H.265 Video", "video"),
    0x0F: ("AAC Audio", "audio"),
    0x11: ("LATM AAC Audio", "audio"),
    0x03: ("MPEG Audio", "audio"),
    0x04: ("MPEG-2 Audio", "audio"),
    0x81: ("AC-3 Audio", "audio"),
    0x06: ("Private/Subtitle/Teletext", "other"),
}
 
LANGUAGE_DESCRIPTOR_TAG = 0x0A  # ISO_639_language_descriptor
 


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
        pat_parsed = False

        # PAT에서 얻은 프로그램 정보
        programs ={}
        pmt_pid_to_program ={}
        network_pid = None
        parsed_pmt_pids =set()

        pid_count ={}

        sync_error_count = 0
        cc_error_count = 0
        unknown_pid_count = 0
        parse_error_count =0

        video_pid = None
        audio_pid = None

        video_codec = None
        audio_codec = None

        pid_map ={}

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
                
                # PMT가 하나 이상 파싱된 후부터 valid_pids 에 없는 PID는 unknown으로 집계
                if parsed_pmt_pids and pid not in valid_pids:
                    unknown_pid_count += 1
                    print(f"[Unknown PID] Packet {count}: PID = {pid}")

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


                # PAT Packet 확인 (이미 파싱했으면 재파싱 안함)
                if pid == 0 and pusi == 1 and not pat_parsed:
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
 
                            print(f"Section Length : {section_length}")
 
                            # 프로그램 목록 순회 (섹션 끝, CRC 4바이트 제외)
                            section_end = pat_start + 3 + section_length - 4
                            entry_start = pat_start + 8
 
                            while entry_start + 4 <= section_end:
                                program_number = (
                                    (packet[entry_start] << 8) | packet[entry_start + 1]
                                )
                                entry_pid = (
                                    ((packet[entry_start + 2] & 0x1F) << 8)
                                    | packet[entry_start + 3]
                                )
 
                                if program_number == 0:
                                    # program_number 0 은 PMT가 아니라 Network PID
                                    network_pid = entry_pid
                                    valid_pids.add(network_pid)
                                    print(f"Network PID    : {network_pid}")
                                else:
                                    programs[program_number] = entry_pid
                                    pmt_pid_to_program[entry_pid] = program_number
                                    valid_pids.add(entry_pid)
                                    pmt_pid = entry_pid  # 하위 호환용 (마지막 프로그램)
                                    print(f"Program Number : {program_number}  ->  PMT PID : {entry_pid}")
 
                                entry_start += 4
 
                            pat_parsed = True
 
                    except IndexError as e:
                        parse_error_count += 1
                        print(f"[PARSE ERROR] Packet {count}: PAT 파싱 중 오류 발생 (범위 초과): {e}")

                # PMT Packet 확인 (프로그램별로 한 번만 파싱)
                if pid in pmt_pid_to_program and pid not in parsed_pmt_pids:

                    try:
                        program_number = pmt_pid_to_program[pid]
                        print(f"\n===== PMT Packet 발견 (Program Number: {program_number}, PMT PID: {pid}) =====")

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

                            codec, media_type = STREAM_TYPE_INFO.get(stream_type, ("Unknown","other"))


                            if media_type == "video":                                
                                video_pid = elementary_pid
                                video_codec = codec
                            elif media_type =="audio":
                                audio_pid = elementary_pid
                                audio_codec = codec

                            # 언어 정보 추출 (ISO_639_language_descriptor, tag 0x0A)
                            language = None
                            descriptor_pos = stream_start + 5
                            descriptor_end = descriptor_pos + es_info_length
 
                            while descriptor_pos + 2 <= descriptor_end:
                                descriptor_tag = packet[descriptor_pos]
                                descriptor_length = packet[descriptor_pos + 1]
 
                                if (descriptor_tag == LANGUAGE_DESCRIPTOR_TAG
                                        and descriptor_length >= 3
                                        and descriptor_pos + 5 <= descriptor_end):
                                    lang_bytes = packet[descriptor_pos + 2: descriptor_pos + 5]
                                    language = lang_bytes.decode("ascii", errors="ignore")
 
                                descriptor_pos += 2 + descriptor_length
                                                        # PID 매핑 정보 저장
                            pid_map[elementary_pid] = {
                                "program_number": program_number,
                                "stream_type": f"0x{stream_type:02X}",
                                "codec": codec,
                                "media_type": media_type,
                                "language": language,
                            }
 
                            print(f"Program Number : {program_number}")
                            print(f"Codec : {codec}")
                            print(f"Stream Type : 0x{stream_type:02X}")
                            print(f"Elementary PID : {elementary_pid}")
                            print(f"ES Info Length : {es_info_length}")
                            print(f"Language : {language if language else '-'}")
                            print()
    
                            # 다음 스트림으로 이동
                            stream_start += 5 + es_info_length

                        #PMT 분석완료
                        parsed_pmt_pids.add(pid)
                        
                    except IndexError as e:
                        parse_error_count += 1
                        print(f"Error: PMT 파싱 중 오류 발생 (범위초과) : {e}") 

            except Exception as e:
                # 개별 패킷 처리 중 오류가 발생해도 중단되지 않음
                parse_error_count += 1
                print(f"Error: 패킷 파싱 중 오류 발생 : {e}")
                continue    
  
    return {
        "total_packets": count,
        "pmt_pid": pmt_pid, # 하위 호환용 (마지막으로 파싱된 PMT PID)
        "pcr_pid": pcr_pid,
        "network_pid": network_pid,
        "programs": programs, # program_number -> pmt_pid
        "video_pid": video_pid,
        "audio_pid": audio_pid,
        "video_codec": video_codec,
        "audio_codec": audio_codec,
        "pid_map": pid_map, # pid -> {program_number, stream_type, codec, media_type, language}
        "sync_error_count": sync_error_count,
        "cc_error_count": cc_error_count,
        "unknown_pid_count": unknown_pid_count,
        "parse_error_count": parse_error_count,
        "pid_count": pid_count,
        "packets": packets
}
