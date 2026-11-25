# 注入 dylib 到 IPA 的脚本
#
# 用法：python inject_dylib.py <原版.ipa> <dylib文件> <输出.ipa>
#
# 做的事：
#   1. 解包 IPA
#   2. 把 dylib 复制进 .app/
#   3. 给主二进制添加 LC_LOAD_DYLIB（指向 @executable_path/xxx.dylib）
#   4. 重新打包

import io, sys, struct, os, shutil, zipfile
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ---- Mach-O load command 补丁 ----

LC_LOAD_DYLIB = 0x0C
MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2

def align8(x):
    return (x + 7) & ~7

def build_dylib_cmd(path_str, cmd_offset):
    """构造 LC_LOAD_DYLIB 结构，路径从 cmd 起始处对齐"""
    name_bytes = path_str.encode('utf-8') + b'\x00'
    # dylib_command: cmd(4) cmdsize(4) name_off(4) timestamp(4)
    #                current_version(4) compat_version(4)
    header_size = 24
    total = align8(header_size + len(name_bytes))
    buf = bytearray(total)
    struct.pack_into('<I', buf, 0, LC_LOAD_DYLIB)
    struct.pack_into('<I', buf, 4, total)
    struct.pack_into('<I', buf, 8, header_size)   # name offset
    struct.pack_into('<I', buf, 12, 2)            # timestamp
    struct.pack_into('<I', buf, 16, 0x00010000)   # current_version
    struct.pack_into('<I', buf, 20, 0x00010000)   # compat_version
    buf[header_size:header_size + len(name_bytes)] = name_bytes
    return bytes(buf)

def inject_load_command(macho_path, dylib_name):
    """
    给 Mach-O 添加 LC_LOAD_DYLIB。
    策略：在 __TEXT 段头部之前找一个可用的 header padding，
          或者在第一个 section 的 file offset 之前插入。
    这里用最稳妥的做法：扩展 header 区域（需要 __TEXT 有足够 padding）。
    """
    d = bytearray(open(macho_path, 'rb').read())

    magic = struct.unpack('<I', d[:4])[0]
    if magic != MH_MAGIC_64:
        raise RuntimeError(f'不是 arm64 Mach-O (magic=0x{magic:x})')

    filetype = struct.unpack('<I', d[12:16])[0]
    ncmds = struct.unpack('<I', d[16:20])[0]
    sizeofcmds = struct.unpack('<I', d[20:24])[0]

    print(f'  原 ncmds={ncmds} sizeofcmds={sizeofcmds}')

    # 找 __TEXT 第一个 section 的 file offset（header 可用空间 = 它到 header 末尾的距离）
    off = 32
    first_section_off = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack('<II', d[off:off + 8])
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = d[off + 8:off + 24].rstrip(b'\x00').decode('ascii', 'ignore')
            nsects = struct.unpack('<I', d[off + 64:off + 68])[0]
            soff = off + 72
            for _s in range(nsects):
                sfoff = struct.unpack('<I', d[soff + 48:soff + 52])[0]
                if sfoff > 0 and (first_section_off is None or sfoff < first_section_off):
                    first_section_off = sfoff
                soff += 80
        off += cmdsize

    header_end = 32 + sizeofcmds
    if first_section_off is None:
        raise RuntimeError('找不到 section file offset')

    free = first_section_off - header_end
    cmd_bytes = build_dylib_cmd(f'@executable_path/{dylib_name}', header_end)
    print(f'  header_end=0x{header_end:x} first_section=0x{first_section_off:x} '
          f'可用空间={free} 需要={len(cmd_bytes)}')

    if free < len(cmd_bytes):
        raise RuntimeError(f'header 空间不足：可用 {free} 字节，需要 {len(cmd_bytes)} 字节')

    # 追加 load command
    d[header_end:header_end + len(cmd_bytes)] = cmd_bytes
    struct.pack_into('<I', d, 16, ncmds + 1)
    struct.pack_into('<I', d, 20, sizeofcmds + len(cmd_bytes))

    open(macho_path, 'wb').write(bytes(d))
    print(f'  已注入 LC_LOAD_DYLIB -> @executable_path/{dylib_name}')


def main():
    if len(sys.argv) < 4:
        print('用法: python inject_dylib.py <原版.ipa> <dylib> <输出.ipa>')
        sys.exit(1)

    src_ipa, dylib_path, out_ipa = sys.argv[1], sys.argv[2], sys.argv[3]
    work = os.path.join(os.path.dirname(out_ipa) or '.', '_inject_work')
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)

    print(f'[1/5] 解包 {src_ipa}')
    with zipfile.ZipFile(src_ipa, 'r') as z:
        z.extractall(work)

    payload = os.path.join(work, 'Payload')
    apps = [x for x in os.listdir(payload) if x.endswith('.app')]
    if not apps:
        raise RuntimeError('Payload 里没有 .app')
    app_dir = os.path.join(payload, apps[0])
    app_name = apps[0]
    print(f'  app = {app_name}')

    # 主二进制名 = .app 名去掉后缀
    exe_name = app_name[:-4]
    exe_path = os.path.join(app_dir, exe_name)
    if not os.path.exists(exe_path):
        # 从 Info.plist 读 CFBundleExecutable
        import plistlib
        info = plistlib.load(open(os.path.join(app_dir, 'Info.plist'), 'rb'))
        exe_name = info.get('CFBundleExecutable')
        exe_path = os.path.join(app_dir, exe_name)
    print(f'  主二进制 = {exe_name}')

    print(f'[2/5] 复制 dylib')
    dylib_name = os.path.basename(dylib_path)
    shutil.copy2(dylib_path, os.path.join(app_dir, dylib_name))

    print(f'[3/5] 注入 LC_LOAD_DYLIB')
    inject_load_command(exe_path, dylib_name)

    print(f'[4/5] 打包 {out_ipa}')
    with zipfile.ZipFile(out_ipa, 'w', zipfile.ZIP_DEFLATED) as zout:
        for root, dirs, files in os.walk(payload):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, work)
                zout.write(full, rel)

    size = os.path.getsize(out_ipa)
    print(f'[5/5] 完成：{out_ipa}  ({size/1024/1024:.1f} MB)')
    print()
    print('注意：这个 IPA 的签名已失效，必须用签名工具重新签名后再安装。')
    print('并且 dylib 也需要一起签（签名工具通常会处理，如果不行要单独签）。')

if __name__ == '__main__':
    main()
