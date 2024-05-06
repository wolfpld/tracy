import lldb

def VectorSummary(value, dict):
    size = value.GetChildMemberWithName('m_size').GetValueAsUnsigned()
    capacity = 1 << value.GetChildMemberWithName('m_capacity').GetValueAsUnsigned()
    magic = bool(value.GetChildMemberWithName('m_magic').GetValueAsUnsigned())
    return 'size={0}, capacity={1}, magic={2}'.format(size, capacity, magic)

def __lldb_init_module(debugger, dict):
    debugger.HandleCommand('type summary add -w tracy -F natvis.VectorSummary -x ^tracy::Vector<.+>')
    debugger.HandleCommand('type category enable tracy')
