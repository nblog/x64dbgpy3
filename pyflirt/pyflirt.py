import struct
import zlib
from io import BytesIO

# ---- constants ----
POLY = 0x8408
R_FLIRT_NAME_MAX = 1024

IDASIG_FEATURE_COMPRESSED = 0x10

# Flirt parse flags
PARSE_MORE_PUBLIC_NAMES           = 0x01
PARSE_READ_TAIL_BYTES             = 0x02
PARSE_READ_REFERENCED_FUNCTIONS   = 0x04
PARSE_MORE_MODULES_WITH_SAME_CRC  = 0x08
PARSE_MORE_MODULES                = 0x10
FUNCTION_LOCAL                    = 0x02
FUNCTION_UNRESOLVED_COLLISION     = 0x08

# ---- core structs ----

class FlirtTailByte:
    def __init__(self, offset, value):
        self.offset = offset
        self.value = value

class FlirtFunction:
    def __init__(self, name, offset, negative_offset=0, is_local=0, is_collision=0):
        self.name = name
        self.offset = offset
        self.negative_offset = negative_offset
        self.is_local = is_local
        self.is_collision = is_collision

class FlirtModule:
    def __init__(self, crc_length, crc16, length, public_functions, tail_bytes, referenced_functions):
        self.crc_length = crc_length
        self.crc16 = crc16
        self.length = length
        self.public_functions = public_functions
        self.tail_bytes = tail_bytes
        self.referenced_functions = referenced_functions

class FlirtNode:
    def __init__(self, length, variant_mask, pattern_bytes, variant_bool_array, modules, children):
        self.length = length
        self.variant_mask = variant_mask
        self.pattern_bytes = pattern_bytes
        self.variant_bool_array = variant_bool_array
        self.modules = modules  # list of FlirtModule
        self.children = children  # list of FlirtNode


def read_u8(f):
    return struct.unpack("B", f.read(1))[0]
def read_u16le(f):
    return struct.unpack("<H", f.read(2))[0]
def read_u16be(f):
    return struct.unpack(">H", f.read(2))[0]
def read_u32le(f):
    return struct.unpack("<I", f.read(4))[0]
def read_u24be(f):
    a, b, c = struct.unpack("BBB", f.read(3))
    return (a << 16) + (b << 8) + c
def read_u32be(f):
    return struct.unpack(">I", f.read(4))[0]

def read_max_2_bytes(f):
    b = read_u8(f)
    if b & 0x80:
        return ((b & 0x7f) << 8) + read_u8(f)
    else:
        return b

def read_multiple_bytes(f):
    b = read_u8(f)
    if (b & 0x80) != 0x80:
        return b
    if (b & 0xC0) != 0xC0:
        return ((b & 0x7F) << 8) + read_u8(f)
    if (b & 0xE0) != 0xE0:
        return ((b & 0x3F) << 24) + (read_u8(f) << 16) + read_u16be(f)
    return read_u32be(f)

# ---- CRC16 (flair version) ----
def crc16(data):
    crc = 0xFFFF
    for ch in data:
        d = ch
        for i in range(8):
            if (crc ^ d) & 1:
                crc = (crc >> 1) ^ POLY
            else:
                crc >>= 1
            d >>= 1
    crc = ~crc & 0xFFFF
    crc = (crc << 8) | ((crc >> 8) & 0xFF)
    return crc & 0xFFFF

# ---- FLIRT parse ----
def parse_header(f):
    magic = f.read(6)
    if magic != b'IDASGN':
        raise Exception("Not a FLIRT file")
    version = read_u8(f)
    arch = read_u8(f)
    file_types = read_u32le(f)
    os_types = read_u16le(f)
    app_types = read_u16le(f)
    features = read_u16le(f)
    old_n_functions = read_u16le(f)
    crc16_v = read_u16le(f)
    ctype = f.read(12)
    library_name_len = read_u8(f)
    ctypes_crc16 = read_u16le(f)
    # Extra for >=6, >=8, >=10
    n_functions = pattern_size = v10unk = None
    if version >= 6:
        n_functions = read_u32le(f)
        if version >= 8:
            pattern_size = read_u16le(f)
            if version >= 10:
                v10unk = read_u16le(f)
    library_name = f.read(library_name_len)
    return {
        'version': version,
        'arch': arch,
        'file_types': file_types,
        'os_types': os_types,
        'app_types': app_types,
        'features': features,
        'old_n_functions': old_n_functions,
        'crc16': crc16_v,
        'ctype': ctype,
        'library_name': library_name,
        'ctypes_crc16': ctypes_crc16,
        'n_functions': n_functions,
        'pattern_size': pattern_size,
        'v10unk': v10unk,
    }

# ---- node/module-tree parse ----
def read_node_variant_mask(f, length):
    if length < 0x10:
        return read_max_2_bytes(f)
    elif length <= 0x20:
        return read_multiple_bytes(f)
    elif length <= 0x40:
        return (read_multiple_bytes(f) << 32) + read_multiple_bytes(f)
    else:
        raise Exception("invalid variant mask len: %x" % length)

def read_node_bytes(f, node_length, variant_mask):
    mask_bit = 1 << (node_length - 1)
    pattern_bytes = []
    variant_bool_array = []
    for _ in range(node_length):
        v = (variant_mask & mask_bit) != 0
        if v:
            pattern_bytes.append(0)
        else:
            pattern_bytes.append(read_u8(f))
        variant_bool_array.append(v)
        mask_bit >>= 1
    return pattern_bytes, variant_bool_array

def parse_module_public_functions(f, version):
    # Returns: (functions, last flags)
    func_list = []
    offset = 0
    while True:
        if version >= 9:
            offset += read_multiple_bytes(f)
        else:
            offset += read_max_2_bytes(f)
        is_local = is_collision = 0
        b = read_u8(f)
        if b < 0x20:
            if b & FUNCTION_LOCAL:
                is_local = 1
            if b & FUNCTION_UNRESOLVED_COLLISION:
                is_collision = 1
            b = read_u8(f)
        name_bytes = []
        while b >= 0x20 and len(name_bytes) < R_FLIRT_NAME_MAX:
            name_bytes.append(b)
            b = read_u8(f)
        name = bytes(name_bytes).decode('ascii', errors='replace')
        func = FlirtFunction(name, offset, 0, is_local, is_collision)
        func_list.append(func)
        flags = b
        if not (flags & PARSE_MORE_PUBLIC_NAMES):
            break
    return func_list, flags

def parse_module_tail_bytes(f, version):
    tail_bytes = []
    num = 1
    if version >= 8:
        num = read_u8(f)
    for _ in range(num):
        if version >= 9:
            offset = read_multiple_bytes(f)
        else:
            offset = read_max_2_bytes(f)
        value = read_u8(f)
        tb = FlirtTailByte(offset, value)
        tail_bytes.append(tb)
    return tail_bytes

def parse_module_referenced_functions(f, version):
    refs = []
    num = 1
    if version >= 8:
        num = read_u8(f)
    for _ in range(num):
        if version >= 9:
            offset = read_multiple_bytes(f)
        else:
            offset = read_max_2_bytes(f)
        namelen = read_u8(f)
        if namelen == 0:
            namelen = read_multiple_bytes(f)
        name_bytes = []
        for _ in range(namelen):
            name_bytes.append(read_u8(f))
        negative_offset = 0
        if len(name_bytes) > 0 and name_bytes[-1] == 0:
            name_bytes = name_bytes[:-1]
            negative_offset = 1
        name = bytes(name_bytes).decode('ascii', errors='replace')
        ref = FlirtFunction(name, offset, negative_offset, 0, 0)
        refs.append(ref)
    return refs

def parse_module(f, version, crc_length, crc16):
    if version >= 9:
        length = read_multiple_bytes(f)
    else:
        length = read_max_2_bytes(f)
    public_functions, flags = parse_module_public_functions(f, version)
    tail_bytes = []
    referenced_functions = []
    if flags & PARSE_READ_TAIL_BYTES:
        tail_bytes = parse_module_tail_bytes(f, version)
    if flags & PARSE_READ_REFERENCED_FUNCTIONS:
        referenced_functions = parse_module_referenced_functions(f, version)
    return FlirtModule(crc_length, crc16, length, public_functions, tail_bytes, referenced_functions), flags

def parse_modules(f, version):
    modules = []
    while True:
        crc_length = read_u8(f)
        crc16 = read_u16be(f)
        while True:
            module, flags = parse_module(f, version, crc_length, crc16)
            modules.append(module)
            if not (flags & PARSE_MORE_MODULES_WITH_SAME_CRC):
                break
        if not (flags & PARSE_MORE_MODULES):
            break
    return modules

def parse_tree(f, version, is_root):
    if is_root:
        node_length = 0
        variant_mask = 0
        pattern_bytes = []
        variant_bool_array = []
    else:
        node_length = read_u8(f)
        variant_mask = read_node_variant_mask(f, node_length)
        pattern_bytes, variant_bool_array = read_node_bytes(f, node_length, variant_mask)
    n_nodes = read_multiple_bytes(f)
    if n_nodes == 0:
        modules = parse_modules(f, version)
        return FlirtNode(node_length, variant_mask, pattern_bytes, variant_bool_array, modules, [])
    children = []
    for _ in range(n_nodes):
        child = parse_tree(f, version, False)
        children.append(child)
    return FlirtNode(node_length, variant_mask, pattern_bytes, variant_bool_array, [], children)

# ---- load FLIRT file ----
def load_flirt_file(filename):
    with open(filename, "rb") as f:
        header = parse_header(f)
        # compressed signature
        if header["features"] & IDASIG_FEATURE_COMPRESSED:
            data = f.read()
            if header["version"] < 7:
                decompr = zlib.decompress(data, -zlib.MAX_WBITS)
            else:
                decompr = zlib.decompress(data)
            f = BytesIO(decompr)
        node = parse_tree(f, header["version"], is_root=True)
        return header, node

# ---- print signature content (like r_sign_flirt_dump) ----
def indent(level):
    return ' ' * (level * 2)

def node_pattern_string(node):
    s = ""
    for i in range(node.length):
        if node.variant_bool_array[i]:
            s += ".."
        else:
            s += "%02X" % node.pattern_bytes[i]
    return s+":"

def print_module(module, indent_str=""):
    s = "%02X %04X %04X " % (module.crc_length, module.crc16, module.length)
    for func in module.public_functions:
        flags = ""
        if func.is_local or func.is_collision:
            flags += "("
            if func.is_local:
                flags += "l"
            if func.is_collision:
                flags += "!"
            flags += ")"
        s += "%s%04X:%s" % (flags, func.offset, func.name)
        s += " "
    for tb in module.tail_bytes:
        s += " (%04X: %02X)" % (tb.offset, tb.value)
    if module.referenced_functions:
        s += " (REF "
        for rf in module.referenced_functions:
            s += "%04X: %s " % (rf.offset, rf.name)
        s = s.rstrip()
        s += ")"
    print(indent_str + s)

def print_node(node, level=-1):
    indent_str = indent(level+1)
    if node.pattern_bytes:
        print(indent_str + node_pattern_string(node))
    if node.children:
        for child in node.children:
            print_node(child, level+1)
    elif node.modules:
        for idx, module in enumerate(node.modules):
            print(indent_str + "  %d. " % idx, end='')
            print_module(module, "")


def match_node_pattern(node, b, buf_off):
    """检查 node 的 pattern 是否和 b 的 buf_off 处数据匹配。"""
    if node.length == 0:
        return True
    if len(b) < buf_off + node.length:
        return False
    for i in range(node.length):
        if not node.variant_bool_array[i]:
            if node.pattern_bytes[i] != b[buf_off + i]:
                return False
    return True

def match_module(module, b, start_addr, base_off, callback=None, verbose=False):
    """
    检查module与b从base_off起的buf是否匹配。
    callback(addr, function_obj): 若匹配则回调函数。
    start_addr: 模式匹配开始时的逻辑地址。
    base_off: 模块数据（CRC等）在缓冲区b中的起始偏移（模式之后）。
    """
    if len(b) < base_off + module.crc_length:
        return False
    data4crc = b[base_off:base_off+module.crc_length]
    actual_crc = crc16(data4crc)
    if module.crc16 != actual_crc:
        if verbose:
            print("CRC fail %04x vs %04x" % (module.crc16, actual_crc))
        return False
    # 检查 tail bytes
    for tb in module.tail_bytes:
        pos = base_off + module.crc_length + tb.offset
        if pos >= len(b):
            return False
        if b[pos] != tb.value:
            if verbose:
                print("Tail fail at", pos, "expect=%02x" % tb.value, "real=%02x"%b[pos])
            return False
    # 忽略 referenced_functions 匹配（实现略）
    if callback:
        for fun in module.public_functions:
            # 使用 start_addr 计算最终地址，而不是 base_off
            callback(start_addr + fun.offset, fun)
    return True

def match_node(node, b, start_addr, buf_off, callback=None, verbose=False):
    """
    递归匹配 node 对应的 pattern + 子节点/模块，如果匹配调用 callback
    start_addr: 模式匹配开始时的逻辑地址 (base_addr + offs)
    buf_off: 当前模式在 buffer b 中的偏移
    """
    if not match_node_pattern(node, b, buf_off):
        return False
    found = False
    next_off = buf_off + node.length
    if node.children:
        for child in node.children:
            # 传递原始的 start_addr 和更新后的 next_off
            if match_node(child, b, start_addr, next_off, callback, verbose):
                found = True
    elif node.modules:
        for module in node.modules:
            # 传递原始的 start_addr 和更新后的 next_off 给 match_module
            if match_module(module, b, start_addr, next_off, callback=callback, verbose=verbose):
                found = True
    return found

def scan_buffer_with_flirt(rootnode, b, base_addr=0, callback=None, verbose=False):
    """
    用FLIRT root节点扫描 buffer b，回调 callback(address, function)。
    base_addr用于外部环境。
    返回所有命中的 (address, FlirtFunction) 列表
    """
    matches = []
    def my_callback(addr, fun):
        # 回调地址现在由 match_module 使用 start_addr + fun.offset 计算
        matches.append((addr, fun)) # addr 已经是 base_addr + start_buf_off + fun.offset
        if callback:
            callback(addr, fun)

    for offs in range(len(b)):
        current_start_addr = base_addr + offs
        for child in rootnode.children:
            # 传递 current_start_addr 作为模式匹配的起始逻辑地址
            if match_node(child, b, current_start_addr, offs, callback=my_callback, verbose=verbose):
                # 如果一个子节点匹配成功，我们通常认为这个位置的函数已经被识别，
                # 可以选择跳出内层循环，避免同一位置被不同模式重复匹配（取决于具体需求）
                # 这里保持原逻辑，继续检查其他子节点，但通常第一个匹配就够了
                pass # 或者 break，如果只需要第一个匹配
    return matches