import json
import random

def generate_trace_file(config):
    trace_file = config["trace_file"]
    num_operations = config["num_operations"]
    params = config["params"]
    probabilities = config["probabilities"]
    seed = config["seed"]

    distribution = config["distribution"]
    dist_function = random.gauss

    if distribution == "uniform":
        dist_function = random.uniform
    elif distribution == "lognormal":
        dist_function = random.lognormvariate
    elif distribution == "exponential":
        dist_function = random.expovariate
    elif distribution == "gamma":
        dist_function = random.gammavariate
    elif distribution == "normal":
        dist_function = random.gauss
    else:
        print(f"Invalid distribution {distribution}, using gaussian distribution")
        params = {
            "mu": 100,
            "sigma": 50
        }

    random.seed(seed)

    allocations = {}  # To track allocated blocks

    stats = {}  # To track stats
    stats["alloc"] = 0
    stats["free"] = 0
    stats["realloc"] = 0
    stats["total"] = 0

    with open(trace_file, "w") as f:
        for index in range(0, num_operations):
            
            if index == 0:
                operation = "malloc"
            else:
                operation = random.choices(["malloc", "free", "realloc"], weights=probabilities)[0]

            # If there are allocated blocks, randomly choose one for free or realloc
            if operation != "malloc" and allocations:
                allocated_index = random.choice(list(allocations.keys()))

                if operation == "free":
                    f.write(f"F {allocated_index}\n")
                    stats["free"] += 1
                    stats["total"] += 1
                    del allocations[allocated_index]
                elif operation == "realloc":
                    allocation_size = max(1, int(dist_function(**params)))
                    stats["realloc"] += 1
                    stats["total"] += 1
                    f.write(f"R {allocated_index} {allocation_size}\n")

            # For malloc, generate a new allocation and track it
            elif operation == "malloc":
                allocation_size = max(1, int(dist_function(**params)))
                allocations[index] = allocation_size
                stats["alloc"] += 1
                stats["total"] += 1
                f.write(f"M {index} {allocation_size}\n")

    print(f"Generated trace file {trace_file} with {stats['total']} operations")

    # put the header in the file
    with open(trace_file, "r") as f:
        content = f.read()
    with open(trace_file, "w") as f:
        f.write(f"{stats['total']}\n")
        f.write(f"{stats['alloc']}\n")
        f.write(f"{stats['free']}\n")
        f.write(f"{stats['realloc']}\n")
        f.write(content)

if __name__ == "__main__":
    with open("trace_config.json", "r") as config_file:
        configs = json.load(config_file)
        for config in configs:
            generate_trace_file(config)