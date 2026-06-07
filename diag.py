from panda import Panda

p = Panda()
h = p.health()

print(p)
print(h)

print()

print("tx_buffer_overflow:", h["tx_buffer_overflow"])
print("rx_buffer_overflow:", h["rx_buffer_overflow"])
print("safety_tx_blocked:", h["safety_tx_blocked"])

for bus in [0, 2]:
    ch = p.can_health(bus)
    print(f"\nBus {bus}:")
    print("  canfd_enabled:", ch["canfd_enabled"])
    print("  bus_off_cnt:", ch["bus_off_cnt"])
    print("  transmit_error_cnt:", ch["transmit_error_cnt"])
    print("  receive_error_cnt:", ch["receive_error_cnt"])
    print("  total_error_cnt:", ch["total_error_cnt"])

    print()
    print(ch)
