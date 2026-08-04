TS_PACKET_SIZE = 188


def make_sync_error(src, dst):
    """첫 번째 패킷의 Sync Byte를 깨뜨림"""

    with open(src, "rb") as f:
        data = bytearray(f.read())

    data[0] = 0x46      # 원래는 0x47

    with open(dst, "wb") as f:
        f.write(data)

    print(f"{dst} 생성 완료")


def get_pid(packet):
    return ((packet[1] & 0x1F) << 8) | packet[2]


TS_PACKET_SIZE = 188


def get_pid(packet):
    return ((packet[1] & 0x1F) << 8) | packet[2]


def make_cc_error(src, dst, target_pid=256, occurrence=2, max_packet_limit=1000):
    """
    target_pid가 파일에서 occurrence번째로 등장하는 패킷의 CC를 깨뜨린다.
    max_packet_limit 이내에 들어오는지 확인하고, 벗어나면 경고를 출력한다.
    """

    with open(src, "rb") as f:
        data = bytearray(f.read())

    total_packets = len(data) // TS_PACKET_SIZE
    count = 0

    for i in range(total_packets):
        offset = i * TS_PACKET_SIZE
        packet = data[offset:offset + TS_PACKET_SIZE]

        if get_pid(packet) != target_pid:
            continue

        count += 1

        if count == occurrence:
            original_cc = packet[3] & 0x0F
            new_cc = (original_cc + 2) % 16

            data[offset + 3] = (data[offset + 3] & 0xF0) | new_cc

            packet_number = i + 1  # 1-based (analyzer.py의 count와 동일한 방식)

            if packet_number > max_packet_limit:
                print(f"[경고] 이 패킷은 {packet_number}번째로, GUI 표시 한도({max_packet_limit})를 벗어납니다.")

            print(f"[CC Error 생성] PID={target_pid}, {occurrence}번째 등장 "
                  f"(packet_index={i}, 패킷 번호={packet_number}, offset={offset})")
            print(f"  원래 CC: {original_cc} -> 변경 CC: {new_cc}")
            break
    else:
        raise ValueError(f"PID {target_pid}가 파일 내에서 {occurrence}번 이상 등장하지 않았습니다. "
                          f"(총 {count}번 등장)")

    with open(dst, "wb") as f:
        f.write(data)

    print(f"{dst} 생성 완료")


if __name__ == "__main__":
    # PID 0(PAT)은 파일 앞부분에 자주 반복 등장하므로 1000번째 이내로 잡힐 가능성이 높음
    make_cc_error("samples/sample.ts", "samples/cc_error.ts", target_pid=0, occurrence=2)


def make_unknown_pid(src, dst):
    """첫 번째 패킷의 PID를 존재하지 않는 값으로 변경"""

    with open(src, "rb") as f:
        data = bytearray(f.read())

    # PID = 8191 (0x1FFF)로 변경
    data[1] = (data[1] & 0xE0) | 0x1F
    data[2] = 0xFF

    with open(dst, "wb") as f:
        f.write(data)

    print(f"{dst} 생성 완료")


if __name__ == "__main__":

    source = "samples/sample.ts"

    make_sync_error(source, "samples/sync_error.ts")
    make_cc_error(source, "samples/cc_error.ts")
    make_unknown_pid(source, "samples/unknown_pid.ts")