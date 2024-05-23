import lldb

def VectorSummary(value, dict):
    v = value.GetNonSyntheticValue()
    size = v.GetChildMemberWithName('m_size').GetValueAsUnsigned()
    capacityVal = v.GetChildMemberWithName('m_capacity').GetValueAsUnsigned()
    capacity = 1 << capacityVal if capacityVal < 63 else 'read-only'
    magic = bool(v.GetChildMemberWithName('m_magic').GetValueAsUnsigned())
    return '{{size={0}, capacity={1}, magic={2}}}'.format(size, capacity, magic)

def ShortPtrSummary(value, dict):
    val = value.GetNonSyntheticValue()
    ptr = val.GetChildMemberWithName('m_ptr')
    type = val.GetType().GetTemplateArgumentType(0)
    p0 = ptr.GetChildAtIndex(0).GetValueAsUnsigned()
    p1 = ptr.GetChildAtIndex(1).GetValueAsUnsigned()
    p2 = ptr.GetChildAtIndex(2).GetValueAsUnsigned()
    p3 = ptr.GetChildAtIndex(3).GetValueAsUnsigned()
    p4 = ptr.GetChildAtIndex(4).GetValueAsUnsigned()
    p5 = ptr.GetChildAtIndex(5).GetValueAsUnsigned()
    #return '0x{0:02x}{1:02x}{2:02x}{3:02x}{4:02x}{5:02x}'.format(p5, p4, p3, p2, p1, p0)
    return value.CreateValueFromAddress('m_ptr', p0 | (p1 << 8) | (p2 << 16) | (p3 << 24) | (p4 << 32) | (p5 << 40), type)

class ShortPtrPrinter:
    def __init__(self, val, dict):
        self.val = val
        self.type = self.val.GetType().GetTemplateArgumentType(0)

    def update(self):
        ptr = self.val.GetChildMemberWithName('m_ptr')
        p0 = ptr.GetChildAtIndex(0).GetValueAsUnsigned()
        p1 = ptr.GetChildAtIndex(1).GetValueAsUnsigned()
        p2 = ptr.GetChildAtIndex(2).GetValueAsUnsigned()
        p3 = ptr.GetChildAtIndex(3).GetValueAsUnsigned()
        p4 = ptr.GetChildAtIndex(4).GetValueAsUnsigned()
        p5 = ptr.GetChildAtIndex(5).GetValueAsUnsigned()
        self.ptr = p0 | (p1 << 8) | (p2 << 16) | (p3 << 24) | (p4 << 32) | (p5 << 40)

    def num_children(self):
        return 1

    def get_child_index(self, name):
        return int(name.lstrip('[').rstrip(']'))

    def get_child_at_index(self, index):
        return self.val.CreateValueFromAddress('m_ptr', self.ptr, self.type)

class VectorPrinter:
    def __init__(self, val, dict):
        self.val = val
        self.magic = bool(val.GetChildMemberWithName('m_magic').GetValueAsUnsigned())
        if self.magic:
            self.type = val.GetType().GetTemplateArgumentType(0).GetTemplateArgumentType(0)
        else:
            self.type = val.GetType().GetTemplateArgumentType(0)
        self.stride = self.type.GetByteSize()

    def update(self):
        ptr = self.val.GetChildMemberWithName('m_ptr').GetChildMemberWithName('m_ptr')
        p0 = ptr.GetChildAtIndex(0).GetValueAsUnsigned()
        p1 = ptr.GetChildAtIndex(1).GetValueAsUnsigned()
        p2 = ptr.GetChildAtIndex(2).GetValueAsUnsigned()
        p3 = ptr.GetChildAtIndex(3).GetValueAsUnsigned()
        p4 = ptr.GetChildAtIndex(4).GetValueAsUnsigned()
        p5 = ptr.GetChildAtIndex(5).GetValueAsUnsigned()
        self.ptr = p0 | (p1 << 8) | (p2 << 16) | (p3 << 24) | (p4 << 32) | (p5 << 40)
        self.size = self.val.GetChildMemberWithName('m_size').GetValueAsUnsigned()

    def num_children(self):
        return self.size

    def get_child_index(self, name):
        return int(name.lstrip('[').rstrip(']'))

    def get_child_at_index(self, index):
        return self.val.CreateValueFromAddress('[%d]' % index, self.ptr + index * self.stride, self.type)

def Int24Summary(value, dict):
    val = value.GetNonSyntheticValue().GetChildMemberWithName('m_val')
    p0 = val.GetChildAtIndex(0).GetValueAsUnsigned()
    p1 = val.GetChildAtIndex(1).GetValueAsUnsigned()
    p2 = val.GetChildAtIndex(2).GetValueAsUnsigned()
    return p0 | (p1 << 8) | (p2 << 16)

def Int48Summary(value, dict):
    val = value.GetNonSyntheticValue().GetChildMemberWithName('m_val')
    p0 = val.GetChildAtIndex(0).GetValueAsUnsigned()
    p1 = val.GetChildAtIndex(1).GetValueAsUnsigned()
    p2 = val.GetChildAtIndex(2).GetValueAsUnsigned()
    p3 = val.GetChildAtIndex(3).GetValueAsUnsigned()
    p4 = val.GetChildAtIndex(4).GetValueAsUnsigned()
    p5 = val.GetChildAtIndex(5).GetValueAsUnsigned()
    return p0 | (p1 << 8) | (p2 << 16) | (p3 << 24) | (p4 << 32) | (p5 << 40)

def __lldb_init_module(debugger, dict):
    lldb.formatters.Logger._lldb_formatters_debug_level = 2
    debugger.HandleCommand('type summary add -w tracy -F natvis.VectorSummary -x ^tracy::Vector<.+>')
    debugger.HandleCommand('type summary add -w tracy -F natvis.ShortPtrSummary -x ^tracy::short_ptr<.+>')
    debugger.HandleCommand('type summary add -w tracy -F natvis.Int24Summary -x ^tracy::Int24')
    debugger.HandleCommand('type summary add -w tracy -F natvis.Int48Summary -x ^tracy::Int48')
    debugger.HandleCommand('type synthetic add -w tracy -l natvis.VectorPrinter -x ^tracy::Vector<.+>')
    debugger.HandleCommand('type synthetic add -w tracy -l natvis.ShortPtrPrinter -x ^tracy::short_ptr<.+>')
    debugger.HandleCommand('type category enable tracy')
