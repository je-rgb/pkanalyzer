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


def make_unknown_pid(src, dst, target_index=50, fake_pid=8191):
    """
    기존 TS 패킷 중 target_index번째 패킷의 PID를 fake_pid로 변경.
    (새 패킷을 삽입하는 게 아니라 원본 패킷 하나를 덮어씀 → 전체 패킷 수는 그대로 유지됨)
    target_index=0(PAT 패킷)은 변경하지 않도록 방지.
    """

    with open(src, "rb") as f:
        data = bytearray(f.read())

    total_packets = len(data) // TS_PACKET_SIZE
    if total_packets < 2:
        raise ValueError("입력 파일에 패킷이 충분하지 않습니다.")

    if target_index == 0:
        raise ValueError("0번째 패킷(PAT)은 변경할 수 없습니다.")
    if not (1 <= target_index < total_packets):
        raise ValueError(f"target_index는 1 이상 {total_packets - 1} 이하여야 합니다.")
    if not (0 <= fake_pid <= 0x1FFF):
        raise ValueError("fake_pid는 0~8191(13비트) 범위여야 합니다.")

    offset = target_index * TS_PACKET_SIZE

    # sync byte(0x47) 확인 (정상적인 TS 패킷 경계인지 체크)
    if data[offset] != 0x47:
        raise ValueError(f"target_index={target_index} 위치가 TS 패킷 경계가 아닙니다.")

    # PID 필드(바이트 1-2)만 수정. transport_error_indicator, payload_unit_start_indicator,
    # transport_priority 등 상위 3비트는 그대로 유지하고 하위 13비트(PID)만 교체
    original_b1 = data[offset + 1]
    top3bits = original_b1 & 0xE0  # 상위 3비트 보존
    data[offset + 1] = top3bits | ((fake_pid >> 8) & 0x1F)
    data[offset + 2] = fake_pid & 0xFF

    with open(dst, "wb") as f:
        f.write(data)

    print(f"{dst} 생성 완료 (target_index={target_index}, PID={fake_pid})")


if __name__ == "__main__":

    source = "samples/sample.ts"

    make_sync_error(source, "samples/sync_error.ts")
    make_cc_error(source, "samples/cc_error.ts")
    make_unknown_pid(source, "samples/unknown_pid.ts")