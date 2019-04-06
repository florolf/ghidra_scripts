#Imports register definitions from an SVD file
#@category Data

from ghidra.program.flatapi import FlatProgramAPI
import xml.etree.ElementTree as ET

# get_text and get_int taken from https://github.com/posborne/cmsis-svd
def get_text(node, tag, default=None):
    try:
        return node.find(tag).text
    except AttributeError:
        return default

def get_int(node, tag, default=None):
    text_value = get_text(node, tag, default)
    try:
        if text_value != default:
            text_value = text_value.strip().lower()
            if text_value.startswith('0x'):
                return int(text_value[2:], 16)  # hexadecimal
            elif text_value.startswith('#'):
                # TODO(posborne): Deal with strange #1xx case better
                #
                # Freescale will sometimes provide values that look like this:
                #   #1xx
                # In this case, there are a number of values which all mean the
                # same thing as the field is a "don't care".  For now, we just
                # replace those bits with zeros.
                text_value = text_value.replace('x', '0')[1:]
                is_bin = all(x in '01' for x in text_value)
                return int(text_value, 2) if is_bin else int(text_value)  # binary
            elif text_value.startswith('true'):
                return 1
            elif text_value.startswith('false'):
                return 0
            else:
                return int(text_value)  # decimal
    except ValueError:
        return default
    return default

def declare(program, file):
    tree = ET.parse(file)
    root = tree.getroot()

    api = FlatProgramAPI(program)
    aspace = api.getAddressFactory().getDefaultAddressSpace()

    periph_map = {}

    for periph in root.findall('.//peripheral'):
        periph_name = get_text(periph, 'name', 'UNK')
        periph_base = get_int(periph, 'baseAddress')

        derived_from = periph.get('derivedFrom')
        if derived_from:
            regs = periph_map[derived_from]
        else:
            regs = periph.findall('./registers/register')

        periph_map[periph_name] = regs

        for reg in regs:
            reg_name = get_text(reg, 'name', 'UNK')
            reg_addr = periph_base + get_int(reg, 'addressOffset')
            reg_size = get_int(reg, 'size')

            addr = aspace.getAddress(reg_addr)
            try:
                api.createLabel(addr,
                                "%s_%s" % (periph_name, reg_name),
                                True)

                if reg_size == 8:
                    api.createByte(addr)
                elif reg_size == 16:
                    api.createWord(addr)
                elif reg_size == 32:
                    api.createDWord(addr)
            except:
                print("skipping address 0x%08x" % reg_addr)

svd_file = askFile("Select SVD file", "OK")

declare(currentProgram, svd_file.path)
