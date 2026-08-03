TS_PACKET_SIZE = 188


def make_sync_error(src, dst):
    """첫 번째 패킷의 Sync Byte를 깨뜨림"""

    with open(src, "rb") as f:
        data = bytearray(f.read())

    data[0] = 0x46      # 원래는 0x47

    with open(dst, "wb") as f:
        f.write(data)

    print(f"{dst} 생성 완료")


def make_cc_error(src, dst):
    """두 번째 패킷의 CC를 변경"""

    with open(src, "rb") as f:
        data = bytearray(f.read())

    # 두 번째 패킷의 시작 offset
    offset = TS_PACKET_SIZE #188

    # Header의 4번째 바이트
    # 하위 4비트가 CC
    data[offset + 3] = (data[offset + 3] & 0xF0) | 0x0F

    with open(dst, "wb") as f:
        f.write(data)

    print(f"{dst} 생성 완료")


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