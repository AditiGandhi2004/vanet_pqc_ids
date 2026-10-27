import csv
import random
import os


OUTPUT_FILE = "results/vanet_ids_dataset.csv"


def generate_normal_sample(sequence):
    speed = random.uniform(40, 80)
    direction = random.uniform(0, 360)
    x = random.uniform(0, 500)
    y = random.uniform(0, 500)

    return [
        speed,
        direction,
        x,
        y,
        sequence,
        1,
        random.choice([1, 2, 3]),
        0,
        random.choice([
    random.uniform(0.0, 0.05),
    random.uniform(0.5, 1.0)
]),
        0
    ]


def generate_replay_sample(sequence):
    speed = random.uniform(40, 80)
    direction = random.uniform(0, 360)
    x = random.uniform(0, 500)
    y = random.uniform(0, 500)

    return [
        speed,
        direction,
        x,
        y,
        sequence,
        1,
        random.choice([1, 2, 3]),
        0,
        random.uniform(0.01, 0.1),
        1
    ]


def generate_sybil_sample(sequence):
    speed = random.uniform(40, 80)
    direction = random.uniform(0, 360)

    x = random.uniform(100, 110)
    y = random.uniform(100, 110)

    return [
        speed,
        direction,
        x,
        y,
        sequence,
        1,
        random.choice([1, 2, 3]),
        1,
        random.uniform(0.2, 1.0),
        2
    ]


def generate_dos_sample(sequence):
    speed = random.uniform(40, 80)
    direction = random.uniform(0, 360)
    x = random.uniform(0, 500)
    y = random.uniform(0, 500)

    return [
        speed,
        direction,
        x,
        y,
        sequence,
        1,
        random.choice([1, 2, 3]),
        1,
        random.uniform(0.001, 0.02),
        3
    ]


def generate_tampering_sample(sequence):
    speed = random.uniform(40, 80)
    direction = random.uniform(0, 360)
    x = random.uniform(0, 500)
    y = random.uniform(0, 500)

    return [
        speed,
        direction,
        x,
        y,
        sequence,
        1,
        3,
        random.choice([-2, -1, 0]),
        random.uniform(0.05, 0.2),
        4
    ]


def main():

    os.makedirs("results", exist_ok=True)

    rows = []

    for i in range(500):
        rows.append(generate_normal_sample(i + 1))

    for i in range(500):
        rows.append(generate_replay_sample(i + 1))

    for i in range(500):
        rows.append(generate_sybil_sample(i + 1))

    for i in range(500):
        rows.append(generate_dos_sample(i + 1))

    for i in range(500):
        rows.append(generate_tampering_sample(i + 1))

    random.shuffle(rows)

    headers = [
        "speed",
        "direction",
        "x",
        "y",
        "sequence_number",
        "has_event",
        "severity",
        "sequence_gap",
        "inter_arrival_time",
        "label"
    ]

    with open(OUTPUT_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)

    print("✓ IDS dataset generated")
    print(f"✓ Samples: {len(rows)}")
    print(f"✓ Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()