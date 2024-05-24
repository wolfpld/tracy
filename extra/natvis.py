import lldb

def VectorSummary(value, dict):
    v = value.GetNonSyntheticValue()
    size = v.GetChildMemberWithName('m_size').GetValueAsUnsigned()
    capacityVal = v.GetChildMemberWithName('m_capacity').GetValueAsUnsigned()
    capacity = 1 << capacityVal if capacityVal < 63 else 'read-only'
    magic = bool(v.GetChildMemberWithName('m_magic').GetValueAsUnsigned())
    return f'{{size={size}, capacity={capacity}, magic={magic}}}'

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

class ZoneEventPrinter:
    def __init__(self, val, dict):
        self.val = val

    def update(self):
        _start_srcloc = self.val.GetChildMemberWithName('_start_srcloc').GetValueAsUnsigned()
        _child2 = self.val.GetChildMemberWithName('_child2').GetValueAsUnsigned()
        _end_child1 = self.val.GetChildMemberWithName('_end_child1').GetValueAsUnsigned()
        self.extra = self.val.GetChildMemberWithName('extra').GetValueAsUnsigned()
        self.start = _start_srcloc >> 16
        self.end = _end_child1 >> 16
        self.srcloc = _start_srcloc & 0xffff
        self.child = ((_end_child1 & 0xffff) << 16) | _child2

    def num_children(self):
        return 5

    def get_child_index(self, name):
        if name == 'start':
            return 0
        if name == 'end':
            return 1
        if name == 'srcloc':
            return 2
        if name == 'child':
            return 3
        if name == 'extra':
            return 4
        return -1

    def get_child_at_index(self, index):
        if index == 0:
            return self.val.CreateValueFromExpression('start', f'int64_t x = {self.start}; x')
        if index == 1:
            return self.val.CreateValueFromExpression('end', f'int64_t x = {self.end}; x')
        if index == 2:
            return self.val.CreateValueFromExpression('srcloc', f'int16_t x = {self.srcloc}; x')
        if index == 3:
            return self.val.CreateValueFromExpression('child', f'int32_t x = {self.child}; x')
        if index == 4:
            return self.val.CreateValueFromExpression('extra', f'uint32_t x = {self.extra}; x')

def RobinHoodSummary(value, dict):
    val = value.GetNonSyntheticValue()
    size = val.GetChildMemberWithName('mNumElements').GetValueAsUnsigned()
    mask = val.GetChildMemberWithName('mMask').GetValueAsUnsigned()
    return f'{{size={size}, load={float(size) / (mask+1)}}}'

def __lldb_init_module(debugger, dict):
    lldb.formatters.Logger._lldb_formatters_debug_level = 2
    debugger.HandleCommand('type summary add -w tracy -F natvis.VectorSummary -x ^tracy::Vector<.+>')
    debugger.HandleCommand('type summary add -w tracy -F natvis.ShortPtrSummary -x ^tracy::short_ptr<.+>')
    debugger.HandleCommand('type summary add -w tracy -F natvis.Int24Summary -x ^tracy::Int24')
    debugger.HandleCommand('type summary add -w tracy -F natvis.Int48Summary -x ^tracy::Int48')
    debugger.HandleCommand('type summary add -w tracy -F natvis.RobinHoodSummary -x ^tracy::detail::Table<.*>')
    debugger.HandleCommand('type synthetic add -w tracy -l natvis.VectorPrinter -x ^tracy::Vector<.+>')
    debugger.HandleCommand('type synthetic add -w tracy -l natvis.ShortPtrPrinter -x ^tracy::short_ptr<.+>')
    debugger.HandleCommand('type synthetic add -w tracy -l natvis.ZoneEventPrinter -x ^tracy::ZoneEvent')
    debugger.HandleCommand('type summary add -w tracy -x ^tracy::ZoneEvent --summary-string "start = ${var.start}, end = ${var.end}, srcloc = ${var.srcloc}, child = ${var.child}, extra = ${var.extra}"')
    debugger.HandleCommand('type category enable tracy')
