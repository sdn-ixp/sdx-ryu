#  Author:
#  Rudiger Birkner (Networked Systems Group ETH Zurich)

from netaddr import *

#                
### VMAC AND VMAC MASK BUILDERS
#

# constructs a match VMAC for checking reachability 
def vmac_participant_match(superset_id, participant_index, sdx):
    
    # add superset identifier
    vmac_bitstring = '{num:0{width}b}'.format(num=int(superset_id), width=(sdx.superset_id_size))
        
    # set bit of participant
    vmac_bitstring += '{num:0{width}b}'.format(num=1, width=(participant_index+1))
    vmac_bitstring += '{num:0{width}b}'.format(num=0, width=(sdx.VMAC_size-len(vmac_bitstring)))

    # convert bitstring to hexstring and then to a mac address
    vmac_addr = '{num:0{width}x}'.format(num=int(vmac_bitstring,2), width=sdx.VMAC_size/4)
    vmac_addr = ':'.join([vmac_addr[i]+vmac_addr[i+1] for i in range(0,sdx.VMAC_size/4,2)])
        
    return vmac_addr

# constructs the accompanying mask for reachability checks
def vmac_participant_mask(participand_index, sdx):
    # a superset which is all 1's
    superset_bits = (1 << sdx.superset_id_size) - 1

    return vmac_participant_match(superset_bits, participant_index, sdx)


# constructs a match VMAC for checking next-hop
def vmac_next_hop_match(participant_name, sdx, inbound_bit = False):
        
    # add participant identifier
    vmac_bitstring = '{num:0{width}b}'.format(num=participant_name, width=(sdx.VMAC_size))

    # set the 'inbound policy required' bit
    if inbound_bit:
        vmac_bitstring = '1' + vmac_bitstring[1:]

    # convert bitstring to hexstring and then to a mac address
    vmac_addr = '{num:0{width}x}'.format(num=int(vmac_bitstring,2), width=sdx.VMAC_size/4)
    vmac_addr = ':'.join([vmac_addr[i]+vmac_addr[i+1] for i in range(0,sdx.VMAC_size/4,2)])
            
    return vmac_addr

# returns a mask on just participant bits
def vmac_next_hop_mask(sdx, inbound_bit = False):
    part_bits_only = (1 << sdx.best_path_size) - 1

    bitmask = vmac_best_path_match(part_bits_only, sdx, inbound_bit)

    return bitmask


# constructs stage-2 VMACs (for both matching and assignment)
def vmac_part_port_match(participant_name, port_num, sdx, inbound_bit = False):
    part_bits = sdx.best_path_size
    remainder = sdx.VMAC_size - part_bits

    # padding and port identifier on the left
    vmac_bitstring_part1 = '{num:0{width}b}'.format(num=port_num, width=remainder)
    # participant identifier on the right
    vmac_bitstring_part2 = '{num:0{width}b}'.format(num=participant_name, width=part_bits)
    # combined
    vmac_bitstring = vmac_bitstring_part1 + vmac_bitstring_part2

    # set the 'inbound policy required' bit
    if inbound_bit:
        vmac_bitstring = '1' + vmac_bitstring[1:]

    # convert bitstring to hexstring and then to a mac address
    vmac_addr = '{num:0{width}x}'.format(num=int(vmac_bitstring,2), width=sdx.VMAC_size/4)
    vmac_addr = ':'.join([vmac_addr[i]+vmac_addr[i+1] for i in range(0,sdx.VMAC_size/4,2)])

    return vmac_addr


# returns a mask on participant and port bits
def vmac_part_port_mask(sdx, inbound_bit = False):
    part_port_size = sdx.best_path_size + sdx.port_size
    part_port_bits = (1 << part_port_size) - 1

    bitmask = vmac_best_path_match(part_port_bits, sdx, inbound_bit)

    return bitmask

# looks like 100000000000000
def vmac_only_first_bit(sdx):

    # return a match on participant 0 with inbound bit set to 1
    return vmac_next_hop_match(0, sdx, inbound_bit=True)




   