import json
import os
import configparser
import matplotlib.pyplot as plt
import seaborn as sns

config = configparser.ConfigParser()
config.read('config/config.ini')
 
results_dir = config['DEFAULT']['results']

read_from = os.path.join(results_dir, "performance.json")

performance_data = []  
with open(read_from, 'r') as file:
    for line in file:
        performance_data.append(json.loads(line.strip())) 

file_sizes = [data["file_size"] for data in performance_data]
build_times = [data["build_tree_time"] for data in performance_data]
hash_times = [data["hash_time"] for data in performance_data]
tree_nodes_count = [data["tree_nodes_count"] for data in performance_data]
encrypt_times = [data["encrypt_time"] for data in performance_data]
decrypt_times = [data["decrypt_time"] for data in performance_data]


plt.figure(figsize=(12, 8))

# Build Tree Time vs File Size
plt.subplot(2, 2, 1)
sns.scatterplot(x=file_sizes, y=build_times, color='blue')
plt.xlabel("File Size (bytes)")
plt.ylabel("Build Tree Time (s)")
plt.title("Build Tree Time vs File Size")

# Hash Time vs Node Count
plt.subplot(2, 2, 2)
sns.scatterplot(x=tree_nodes_count, y=hash_times, color='blue')
plt.xlabel("Node Count")
plt.ylabel("Hash Time (s)")
plt.title("Hash Time vs Node Count")

# Encrypt & Decrypt Time vs File Size
plt.subplot(2, 2, 3)
encrypt_times = [x/1e6 for x in encrypt_times] 
sns.violinplot(y=encrypt_times, x=file_sizes)
#sns.boxenplot(y=decrypt_times, x=file_sizes, marker='o', label="Decrypt Time", color='red')
plt.xlabel("File Size (MB)")
plt.ylabel("Time (s)")
plt.title("Encrypt & Decrypt Time vs File Size")
plt.legend()

#Encrypt & Decrypt Time vs File Size
plt.subplot(2, 2, 4)
sns.lineplot(y=encrypt_times, x=tree_nodes_count, marker='o', label="Encrypt Time", color='green')
sns.lineplot(y=decrypt_times, x=tree_nodes_count, marker='o', label="Decrypt Time", color='red')
plt.xlabel("Node Count")
plt.ylabel("Time (s)")
plt.title("Encrypt & Decrypt Time vs Node Count")
plt.legend()


plt.tight_layout()
#plt.show()
plt.savefig(os.path.join(results_dir, "performance.png"))

