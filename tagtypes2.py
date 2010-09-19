# mapping name to number
tagtypes = {}
tagtypes['unknown'] = 0
tagtypes['custom'] = 1
tagtypes['uint8'] = 2
tagtypes['uint16'] = 3
tagtypes['uint32'] = 4
tagtypes['uint64'] = 5
tagtypes['string'] = 6
tagtypes['double'] = 7
tagtypes['ipv4'] = 8
tagtypes['hash16'] = 9

# reverse mapping number to name
tagtypes_rev = {}
tagtypes_rev[0] = 'unknown'
tagtypes_rev[1] = 'custom'
tagtypes_rev[2] = 'uint8'
tagtypes_rev[3] = 'uint16'
tagtypes_rev[4] = 'uint32'
tagtypes_rev[5] = 'uint64'
tagtypes_rev[6] = 'string'
tagtypes_rev[7] = 'double'
tagtypes_rev[8] = 'ipv4'
tagtypes_rev[9] = 'hash16'
