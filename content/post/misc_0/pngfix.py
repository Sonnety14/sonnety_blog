#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTF PNG 宽高自动恢复器（Python 3.8+，仅标准库即可运行）。

用法：
  python pngfix.py input.png                        # 输出 input_fixed.png
  python pngfix.py input.png output.png             # 自动反推
  python pngfix.py input.png output.png 1500 1500    # 手动尺寸，也必须通过校验
  python pngfix.py input.png --adam7-max-width 200000
  python pngfix.py input.png --max-raw-mib 512 --overwrite

可选：python -m pip install Pillow，增加实际解码检查。

假设：只有 IHDR 宽/高及其 CRC 可能被修改，其他 IHDR 参数和 IDAT 完整。
非隔行：枚举解压长度的约数，求出全部合法宽高，不再限制宽度 8000。
Adam7：逐宽度求解七个 pass 的总长度，默认搜索到 65536（可调整）。
两者均校验每行过滤类型 0..4，并优先采用原 IHDR CRC 匹配的候选。
CRC 已被重算/破坏时，尺寸不一定能唯一恢复；能解码也不代表原尺寸。
有歧义时自动导出候选图片和 report.json，不冒充已经找到唯一原图。
除 IHDR 宽高和 CRC 外，输出所有字节原样保留，包括 IEND 后附加数据。
不修复其他 chunk 的 CRC、损坏的压缩流、位深/颜色类型等；拒绝 APNG。

退出码：0=已输出；1=输入/校验/IO 错误；2=命令行错误；
        3=有歧义，候选已导出；130=用户中断。
依据：https://www.w3.org/TR/png-3/ （IHDR、IDAT、过滤、Adam7、CRC）。
"""
import argparse
import io
import json
import math
import os
from pathlib import Path
import struct
import sys
import tempfile
import warnings
import zlib
from dataclasses import dataclass

SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_DIM = (1 << 31) - 1
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8),
          4: (8, 16), 6: (8, 16)}
# x 起点、y 起点、x 步长、y 步长。
ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8),
         (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))


class PNGError(Exception):
    pass


@dataclass
class PNG:
    data: bytes
    width: int
    height: int
    depth: int
    color: int
    interlace: int
    crc: int
    idat: list
    trailing: int

    @property
    def bpp(self):
        return CHANNELS[self.color] * self.depth

    def header(self, width, height):
        return struct.pack(">II", width, height) + self.data[24:29]

    def crc_matches(self, width, height):
        return zlib.crc32(b"IHDR" + self.header(width, height)) == self.crc

    def patched(self, width, height):
        header = self.header(width, height)
        return (self.data[:16] + header +
                struct.pack(">I", zlib.crc32(b"IHDR" + header)) + self.data[33:])


def parse(data):
    """严格检查结构；只允许 IHDR CRC 以及宽高字段存在错误。"""
    if not data.startswith(SIGNATURE):
        raise PNGError("不是 PNG：文件签名不正确。")
    view = memoryview(data)
    off, chunks = 8, 0
    header = None
    stored_crc = None
    idat = []
    seen_idat = closed_idat = seen_plte = ended = False
    while off < len(data):
        chunks += 1
        if chunks > 100000:
            raise PNGError("chunk 数超过 100000，停止解析。")
        if off + 12 > len(data):
            raise PNGError("chunk 头或 CRC 被截断（偏移 %d）。" % off)
        length = struct.unpack_from(">I", data, off)[0]
        kind = data[off + 4:off + 8]
        if length > MAX_DIM or length > len(data) - off - 12:
            raise PNGError("chunk 长度越界（偏移 %d）。" % off)
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind) or kind[2] & 32:
            raise PNGError("chunk 类型非法（偏移 %d）。" % off)
        end = off + 12 + length
        body = view[off + 8:end - 4]
        crc = struct.unpack_from(">I", data, end - 4)[0]
        if kind != b"IHDR" and zlib.crc32(view[off + 4:end - 4]) != crc:
            raise PNGError("%s CRC 错误；问题不只在宽高，未修改文件。" % kind.decode())
        if chunks == 1 and kind != b"IHDR":
            raise PNGError("IHDR 必须是首个 chunk。")
        if kind == b"IHDR":
            if chunks != 1 or length != 13:
                raise PNGError("IHDR 重复、位置错误或长度不等于 13。")
            header = struct.unpack(">IIBBBBB", body)
            width, height, depth, color, compression, filtering, interlace = header
            if color not in DEPTHS or depth not in DEPTHS[color]:
                raise PNGError("非法位深/颜色类型；本工具只恢复宽高。")
            if compression != 0 or filtering != 0 or interlace not in (0, 1):
                raise PNGError("不支持或已损坏的压缩/过滤/隔行字段。")
            stored_crc = crc
        elif kind in (b"acTL", b"fcTL", b"fdAT"):
            raise PNGError("检测到 APNG，动画帧尺寸需要独立处理，本工具不修改。")
        elif kind == b"PLTE":
            if seen_plte or seen_idat or not length or length % 3 or length > 768:
                raise PNGError("PLTE 长度、数量或位置不合法。")
            if color in (0, 4) or (color == 3 and length // 3 > (1 << depth)):
                raise PNGError("PLTE 与颜色类型/位深不匹配。")
            seen_plte = True
        elif kind == b"IDAT":
            if closed_idat:
                raise PNGError("IDAT 必须连续出现。")
            if color == 3 and not seen_plte:
                raise PNGError("索引色 PNG 缺少前置 PLTE。")
            seen_idat = True
            idat.append(body)
        elif kind == b"IEND":
            if length != 0 or not seen_idat:
                raise PNGError("IEND 非空或缺少 IDAT。")
            off = end
            ended = True
            break
        elif not kind[0] & 32:
            raise PNGError("未知关键 chunk：%s。" % kind.decode())
        if seen_idat and kind != b"IDAT":
            closed_idat = True
        off = end
    if not ended or header is None:
        raise PNGError("缺少 IHDR 或 IEND，文件不完整。")
    return PNG(data, width, height, depth, color, interlace, stored_crc,
               idat, len(data) - off)


def decompress_idat(png, limit):
    """分块、有上限地解压；验证 zlib 校验和、结束标记及多余压缩数据。"""
    decoder = zlib.decompressobj()
    raw = bytearray()
    try:
        for chunk in png.idat:
            for start in range(0, len(chunk), 65536):
                pending = chunk[start:start + 65536]
                if decoder.eof:
                    raise PNGError("zlib 流结束后 IDAT 仍有额外数据，不能仅按宽高修复。")
                while len(pending):
                    part = decoder.decompress(pending, min(1048576, limit - len(raw) + 1))
                    raw.extend(part)
                    if len(raw) > limit:
                        raise PNGError("IDAT 解压超过限制；确有需要时调大 --max-raw-mib。")
                    if decoder.unused_data:
                        raise PNGError("IDAT 含额外压缩流或流外数据。")
                    pending = decoder.unconsumed_tail
    except zlib.error as exc:
        raise PNGError("IDAT zlib 解压/校验失败：%s" % exc) from exc
    if not decoder.eof:
        raise PNGError("IDAT 压缩流被截断，缺少完整 zlib 结束标记。")
    if not raw:
        raise PNGError("IDAT 解压为空。")
    return raw


def extent(size, start, step):
    return max(0, (size - start + step - 1) // step)


def layout(width, height, bpp, interlace):
    """返回各非空 pass 的 (每行含过滤字节的长度, 行数)。"""
    if not interlace:
        return [(1 + (width * bpp + 7) // 8, height)]
    result = []
    for x, y, dx, dy in ADAM7:
        pw, ph = extent(width, x, dx), extent(height, y, dy)
        if pw and ph:
            result.append((1 + (pw * bpp + 7) // 8, ph))
    return result


def expected_size(width, height, bpp, interlace):
    return sum(stride * rows for stride, rows in layout(width, height, bpp, interlace))


def valid_scanlines(raw, width, height, bpp, interlace):
    if not (1 <= width <= MAX_DIM and 1 <= height <= MAX_DIM):
        return False
    passes = layout(width, height, bpp, interlace)
    if sum(stride * rows for stride, rows in passes) != len(raw):
        return False
    offset = 0
    for stride, rows in passes:
        # 先检查少量行以尽早剔除；再用限长切片检查全部行，避免大临时副本。
        for row in range(min(rows, 32)):
            if raw[offset + row * stride] > 4:
                return False
        for row in range(32, rows, 65536):
            stop = min(rows, row + 65536)
            if max(raw[offset + row * stride:offset + stop * stride:stride], default=0) > 4:
                return False
        offset += stride * rows
    return True


def divisors(number):
    for small in range(1, math.isqrt(number) + 1):
        if number % small == 0:
            yield small
            if small * small != number:
                yield number // small


def size_candidates(size, bpp, interlace, adam7_max_width):
    if not interlace:
        # S = h * (1 + ceil(w*bpp/8))。低位深要保留同一字节的多个宽度。
        for stride in divisors(size):
            rowbytes = stride - 1
            if rowbytes <= 0:
                continue
            height = size // stride
            low = ((rowbytes - 1) * 8) // bpp + 1
            high = (rowbytes * 8) // bpp
            if height <= MAX_DIM:
                for width in range(low, min(high, MAX_DIM) + 1):
                    yield width, height
        return
    # h = 8*q+r (r=1..8)。每增加 8 行，各 pass 增加固定行数，
    # 故 S(w,h)=q*A(w)+B(w,r)，无需对高度做第二重穷举。
    upper = min(adam7_max_width, MAX_DIM, size * 8 // bpp)
    for width in range(1, upper + 1):
        passes = [(1 + (extent(width, x, dx) * bpp + 7) // 8, y, dy)
                  for x, y, dx, dy in ADAM7 if extent(width, x, dx)]
        step_size = sum(stride * (8 // dy) for stride, y, dy in passes)
        for residue in range(1, 9):
            base = sum(stride * extent(residue, y, dy) for stride, y, dy in passes)
            quotient, remainder = divmod(size - base, step_size)
            if quotient >= 0 and remainder == 0:
                height = 8 * quotient + residue
                if height <= MAX_DIM:
                    yield width, height


def solve(png, raw, adam7_max_width):
    candidates = set(size_candidates(len(raw), png.bpp, png.interlace, adam7_max_width))
    # 即使声明宽度超出 Adam7 搜索范围，也检查声明尺寸和保留宽度的恢复结果。
    if png.interlace and 1 <= png.width <= MAX_DIM and png.width > adam7_max_width:
        step = expected_size(png.width, 16, png.bpp, 1) - expected_size(png.width, 8, png.bpp, 1)
        for residue in range(1, 9):
            base = expected_size(png.width, residue, png.bpp, 1)
            q, r = divmod(len(raw) - base, step)
            if q >= 0 and r == 0:
                candidates.add((png.width, q * 8 + residue))
    good = [(w, h) for w, h in candidates if valid_scanlines(raw, w, h, png.bpp, png.interlace)]
    # 排序只影响候选展示，不用于将猜测冒充唯一解。
    good.sort(key=lambda wh: (not png.crc_matches(*wh), wh[0] != png.width,
                             wh[1] != png.height, abs(wh[0] - wh[1]), wh))
    hits = [wh for wh in good if png.crc_matches(*wh)]
    if len(hits) == 1:
        return hits, "原 IHDR CRC、扫描行长度及过滤字节同时匹配"
    if len(hits) > 1:
        return hits, "多个候选命中 CRC（CRC32 存在碰撞），无法唯一确定"
    if len(good) == 1:
        return good, "唯一通过长度与过滤字节检查的候选（原 CRC 无匹配）"
    return good, "原 CRC 无匹配，存在多个结构合法候选，无法唯一确定"


def check_decode(data, width, height, use_pillow, max_pixels):
    if not use_pillow:
        return "仅结构校验（--no-pillow）"
    try:
        from PIL import Image
    except ImportError:
        return "仅结构校验（可安装 Pillow 增加解码检查）"
    if width * height > max_pixels:
        return "仅结构校验（像素数超过 --max-decode-pixels，跳过 Pillow）"
    old_limit = Image.MAX_IMAGE_PIXELS
    try:
        Image.MAX_IMAGE_PIXELS = max_pixels
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with Image.open(io.BytesIO(data)) as image:
                if image.format != "PNG" or image.size != (width, height):
                    raise PNGError("Pillow 读到的格式/尺寸不符合预期。")
                image.load()
        return "Pillow 实际解码通过"
    except Exception as exc:
        raise PNGError("Pillow 解码失败：%s" % exc) from exc
    finally:
        Image.MAX_IMAGE_PIXELS = old_limit


def write_atomic(path, data, overwrite=False):
    """先写同目录临时文件；默认以硬链接原子发布，防止覆盖已有输出。"""
    fd, name = tempfile.mkstemp(prefix=".pngfix-", dir=str(path.parent))
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(str(temp), str(path))
        else:
            try:
                os.link(str(temp), str(path))
            except FileExistsError as exc:
                raise PNGError("输出已存在：%s；更换文件名或使用 --overwrite。" % path) from exc
            except OSError:
                # 部分 FAT/共享盘不支持硬链接：仍用独占创建保护现有文件。
                stream = path.open("xb")
                try:
                    with stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                except BaseException:
                    path.unlink()
                    raise
    finally:
        if temp.exists():
            temp.unlink()


def positive(value):
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("必须是正整数") from exc
    if result <= 0:
        raise argparse.ArgumentTypeError("必须是正整数")
    return result


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", type=Path, help="输入 PNG")
    parser.add_argument("output", type=Path, nargs="?", help="输出路径，默认 原名_fixed.png")
    parser.add_argument("width", type=positive, nargs="?", help="可选：手动宽度")
    parser.add_argument("height", type=positive, nargs="?", help="可选：手动高度")
    parser.add_argument("--overwrite", action="store_true", help="允许覆盖已有输出，仍禁止覆盖输入")
    parser.add_argument("--adam7-max-width", type=positive, default=65536, help="Adam7 枚举宽度上限，默认 65536")
    parser.add_argument("--max-file-mib", type=positive, default=128, help="输入文件大小上限 MiB，默认 128")
    parser.add_argument("--max-raw-mib", type=positive, default=256, help="解压大小上限 MiB，默认 256")
    parser.add_argument("--max-decode-pixels", type=positive, default=64000000, help="Pillow 解码像素数上限，默认 64000000")
    parser.add_argument("--export-limit", type=positive, default=20, help="歧义时最多导出几张候选图，默认 20")
    parser.add_argument("--no-pillow", action="store_true", help="只执行内置结构检查，不调用 Pillow")
    return parser


def run(args):
    src = args.source.expanduser().resolve()
    # 不解析输出末尾的符号链接；--overwrite 替换链接本身，避免写入链接目标。
    dst = args.output.expanduser().absolute() if args.output else src.with_name(src.stem + "_fixed.png")
    if src == dst.resolve() or (dst.exists() and os.path.samefile(str(src), str(dst))):
        raise PNGError("禁止覆盖输入原文件，请使用不同输出路径。")
    if dst.exists() and not args.overwrite:
        raise PNGError("输出已存在：%s；更换文件名或使用 --overwrite。" % dst)
    if not dst.parent.is_dir():
        raise PNGError("输出目录不存在：%s" % dst.parent)
    if not src.is_file():
        raise PNGError("输入不是普通文件：%s" % src)
    limit = args.max_file_mib * 1024 * 1024
    if src.stat().st_size > limit:
        raise PNGError("输入文件超过 --max-file-mib 限制。")
    with src.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise PNGError("输入文件超过 --max-file-mib 限制。")
    png = parse(data)
    raw = decompress_idat(png, args.max_raw_mib * 1024 * 1024)
    print("当前声明：%d x %d；位深 %d，颜色类型 %d，隔行 %d" %
          (png.width, png.height, png.depth, png.color, png.interlace))
    print("IHDR CRC：%08x（%s）；IDAT 解压：%d 字节" %
          (png.crc, "与当前头匹配" if png.crc_matches(png.width, png.height) else "与当前头不匹配", len(raw)))
    if png.trailing:
        print("提示：IEND 后有 %d 字节附加数据，将原样保留。" % png.trailing)
    if args.width is not None:
        if not valid_scanlines(raw, args.width, args.height, png.bpp, png.interlace):
            raise PNGError("手动宽高不满足 PNG 范围、扫描行长度或过滤字节要求，未写出。")
        candidates, reason = [(args.width, args.height)], "用户指定，结构校验通过"
    else:
        if png.interlace:
            print("Adam7 搜索宽度：1..%d；也检查当前声明宽度。唯一性仅针对此范围。" % args.adam7_max_width)
        candidates, reason = solve(png, raw, args.adam7_max_width)
        if not candidates:
            raise PNGError("未找到合法尺寸；可能超出 Adam7 搜索范围，或受损字段不止宽高。")
    if len(candidates) == 1:
        width, height = candidates[0]
        fixed = png.patched(width, height)
        checked = check_decode(fixed, width, height, not args.no_pillow, args.max_decode_pixels)
        write_atomic(dst, fixed, args.overwrite)
        print("输出尺寸：%d x %d；依据：%s" % (width, height, reason))
        print("验证：%s" % checked)
        print("已写出：%s（只改 IHDR 宽高及 CRC，其余字节原样保留）" % dst)
        return 0
    # 不能唯一判定时，只写带尺寸名称的候选，不创建具有误导性的单一输出。
    folder = Path(tempfile.mkdtemp(prefix=dst.stem + "_candidates_", dir=str(dst.parent)))
    print("找到 %d 个候选：%s" % (len(candidates), reason))
    report = {"source": str(src), "declared": [png.width, png.height], "reason": reason,
              "adam7_max_width": args.adam7_max_width if png.interlace else None,
              "export_limit": args.export_limit, "candidates": []}
    exported = 0
    for width, height in candidates:
        row = {"width": width, "height": height, "crc_match": png.crc_matches(width, height)}
        if exported < args.export_limit:
            fixed = png.patched(width, height)
            try:
                checked = check_decode(fixed, width, height, not args.no_pillow, args.max_decode_pixels)
            except PNGError as exc:
                row["decode_error"] = str(exc)
            else:
                name = "%dx%d.png" % (width, height)
                write_atomic(folder / name, fixed)
                row.update(file=name, validation=checked)
                exported += 1
                print("  候选：%d x %d%s" % (width, height, " [CRC 匹配]" if row["crc_match"] else ""))
        report["candidates"].append(row)
    write_atomic(folder / "report.json", json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
    print("已导出 %d 张候选及完整清单：%s" % (exported, folder))
    print("候选能解码不等于原尺寸正确。看图选定后可用手动宽高命令生成指定输出。")
    return 3


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.width is None) != (args.height is None):
        parser.error("手动模式需要同时提供输出路径、宽度和高度。")
    if args.width is not None and (args.width > MAX_DIM or args.height > MAX_DIM):
        parser.error("宽高必须在 1..2147483647 范围内。")
    try:
        return run(args)
    except (PNGError, OSError, ValueError, OverflowError, MemoryError) as exc:
        print("错误：%s" % (str(exc) or type(exc).__name__), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
