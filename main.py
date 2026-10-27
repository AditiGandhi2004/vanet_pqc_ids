from simulator.vehicle import Vehicle
from simulator.network import VANETNetwork
from security.pseudonym import PseudonymManager

# Create vehicles
v1 = Vehicle("V01", 0, 0, 60, 0)
v2 = Vehicle("V02", 100, 0, 55, 0)
v3 = Vehicle("V03", 250, 0, 70, 0)
v4 = Vehicle("V04", 500, 0, 65, 180)

# Create pseudonym manager
pseudonym_manager = PseudonymManager()

# Assign pseudonyms
for vehicle in [v1, v2, v3, v4]:
    pseudonym = pseudonym_manager.generate_pseudonym(vehicle.vehicle_id)
    vehicle.set_pseudonym(pseudonym)
    print(f"{vehicle.vehicle_id} -> {vehicle.pseudonym}")

# Create VANET
network = VANETNetwork(communication_range=300)

# Add vehicles
for vehicle in [v1, v2, v3, v4]:
    network.add_vehicle(vehicle)

# Create accident message
message = v1.create_event_message("ACCIDENT", "HIGH")

print("\nGenerated VANET message:")
print(message)

# Broadcast
network.broadcast(v1, message)

# Test replay
print("\n--- REPLAY ATTACK ---")
network.broadcast(v1, message)
