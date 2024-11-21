import json
import os
import configparser
import matplotlib.pyplot as plt
import seaborn as sns
import pandas


config = configparser.ConfigParser()
config.read('config/config.ini')
results_dir = config['DEFAULT']['results']

# read_from = os.path.join(results_dir, "performance_intellectual_property_policy.json")
read_from = os.path.join(results_dir, "performance_weaknesses_policy.json")

performance_data = []  
with open(read_from, 'r') as file:
    for line in file:
        performance_data.append(json.loads(line.strip())) 

records = pandas.DataFrame.from_records(performance_data)

# replace zero values with NaN to prevent division by 0
records['encrypt_to_sbom_percentage_increase'] = (
    (records['encrypted_tree_storage'] - records['sbom_tree_storage']) 
    / records['sbom_tree_storage'].replace(0, pandas.NA) * 100
)

records['decrypt_to_encrypt_percentage_increase'] = (
    (records['decrypted_tree_storage'] - records['encrypted_tree_storage']) 
    / records['encrypted_tree_storage'].replace(0, pandas.NA) * 100
)

# average percentage increase for both cases, ignoring NaN values
average_encrypt_to_sbom_increase = records['encrypt_to_sbom_percentage_increase'].mean()
average_decrypt_to_encrypt_increase = records['decrypt_to_encrypt_percentage_increase'].mean()

print(f"Average Percentage Increase from SBOM Tree Size to Encrypted Tree Size: {average_encrypt_to_sbom_increase:.2f}%")
print(f"Average Percentage Increase from Encrypted Tree Size to Decrypted Tree Size: {average_decrypt_to_encrypt_increase:.2f}%")

# diff between encrypted and initial sbom
records['storage_difference'] = records['encrypted_tree_storage'] - records['sbom_tree_storage']
max_diff_row = records.loc[records['storage_difference'].idxmax()]

# print("Entry with the largest diff between encrypted and initial sbom:")
# print(max_diff_row)

ratio = records['encrypted_tree_storage'] / records['sbom_tree_storage'].replace(0, pandas.NA)
print(f"Ratio of encrypted_tree_storage to sbom_tree_storage: {ratio.mean()}")

# normalize values to MB, ms and 10's of thousands of nodes
records['file_size'] = records['file_size'].apply(lambda x: int(x/1e6)) #MB
records['sbom_tree_storage'] = records['sbom_tree_storage'].apply(lambda x: int(x/1e6)) #MB
records['encrypted_tree_storage'] = records['encrypted_tree_storage'].apply(lambda x: int(x/1e6)) #MB
records['decrypted_tree_storage'] = records['decrypted_tree_storage'].apply(lambda x: int(x/1e6)) #MB
records['build_tree_time'] = records['build_tree_time'].apply(lambda x: int(x/1e-3)) #ms
records['hash_time'] = records['hash_time'].apply(lambda x: int(x/1e-3)) #ms
records['encrypt_time'] = records['encrypt_time'].apply(lambda x: int(x/1e-3)) #ms
records['decrypt_time'] = records['decrypt_time'].apply(lambda x: int(x/1e-3)) #ms
records['tree_nodes_count'] = records['tree_nodes_count'].apply(lambda x: int(x/1e4)) #10k

# k = 200
# of_interest= records['decrypted_tree_storage']
# max_value = max(of_interest)

# print("For decrypted_tree_storage")
# for start in range(1, max_value + 1, k):
#     end = start + k - 1
#     # count the numbers that fall within this range
#     count = sum(1 for x in of_interest if start <= x <= end)
#     print(f"Range {start}-{end}: {count} sboms")


# filter out excessively large nodes 
# records = records.loc[records['decrypted_tree_storage'] <= 200]
#import pdb; pdb.set_trace()

# filter out measurements that do not have enough occurrences (more than 5 here)
OCCURRENCE_MIN = 5
_filter = records.file_size.value_counts()
records = records[records.file_size.isin(_filter.index[_filter.gt(OCCURRENCE_MIN)])]


output_dir = os.path.join(results_dir, "weaknesses_policy")
# output_dir = os.path.join(results_dir, "aes")
os.makedirs(output_dir, exist_ok=True)

def save_violin_plot(data, y, x, ylabel, xlabel, palette, ylim=None, xtick_interval=None):
    plt.figure(figsize=(8, 6))
    sns.violinplot(data=data, y=y, x=x, cut=0, palette=palette)
    plt.xlabel(xlabel, fontsize=24)
    plt.ylabel(ylabel, fontsize=24)
    plt.legend(fontsize=16)
    plt.xticks(fontsize=16)
    plt.yticks(fontsize=16)

    if ylim:
        plt.ylim(ylim)
    if xtick_interval:
        plt.xticks(ticks=plt.xticks()[0][::xtick_interval])
    

    plt.tight_layout()
    sns.despine()
    filename = os.path.join(output_dir, f"{y}_vs_{x}.png")
    plt.savefig(filename, dpi=300)
    plt.close()

#configurations for each plot
plot_configs = [
    {"y": "build_tree_time", "x": "file_size", "ylabel": "Build Tree Time (ms)", "xlabel": "File Size (MB)", "palette": "tab20"},
    {"y": "hash_time", "x": "tree_nodes_count", "ylabel": "Hash Time (ms)", "xlabel": "Node Count (100K)", "palette": "tab20", "xtick_interval": 4},
    {"y": "encrypt_time", "x": "file_size", "ylabel": "Encrypt Time (ms)", "xlabel": "File Size (MB)", "palette": "tab20", "xtick_interval": 4},
    {"y": "decrypt_time", "x": "file_size", "ylabel": "Decrypt Time (ms)", "xlabel": "File Size (MB)", "palette": "tab20", "xtick_interval": 4},
    {"y": "encrypt_time", "x": "tree_nodes_count", "ylabel": "Encrypt Time (ms)", "xlabel": "Node Count (100K)", "palette": "tab20", "xtick_interval": 4},
    {"y": "decrypt_time", "x": "tree_nodes_count", "ylabel": "Decrypt Time (ms)", "xlabel": "Node Count (100K)", "palette": "tab20", "xtick_interval": 4},
    {"x": "file_size", "y": "tree_nodes_count", "xlabel": "File Size (MB)", "ylabel": "Node Count (100K)", "palette": "tab20", "xtick_interval": 4},
    # {"y": "sbom_tree_storage", "x": "tree_nodes_count", "ylabel": "SBOM Tree Size (MB)", "xlabel": "Node Count (100K)", "palette": "tab20", "ylim": (0, 200), "xtick_interval": 4},
    {"y": "sbom_tree_storage", "x": "file_size", "ylabel": "SBOM Tree Size (MB)", "xlabel": "File Size (MB)", "palette": "tab20", "xtick_interval": 4},
    {"y": "encrypted_tree_storage", "x": "file_size", "ylabel": "Encrypted Tree Size (MB)", "xlabel": "File Size (MB)", "palette": "tab20", "xtick_interval": 4},
    {"y": "decrypted_tree_storage", "x": "file_size", "ylabel": "Decrypted Tree Size (MB)", "xlabel": "File Size (MB)", "palette": "tab20", "xtick_interval": 4}
]

# generate and save each plot
for config in plot_configs:
    save_violin_plot(
        data=records,
        y=config["y"],
        x=config["x"],
        ylabel=config["ylabel"],
        xlabel=config["xlabel"],
        palette=config["palette"],
        ylim=config.get("ylim"),
        xtick_interval=config.get("xtick_interval")
    )

records_long = pandas.melt(records, id_vars=["file_size"], 
                       value_vars=["encrypt_time", "decrypt_time"],
                       var_name="Metric", value_name="Time")   

plt.figure(figsize=(10, 6))
sns.violinplot(data=records_long, x="file_size", y="Time", hue="Metric", dodge=True)
plt.xlabel("File Size (MB)")
plt.ylabel("Time (ms)")
plt.xticks(ticks=plt.xticks()[0][::3]) 
plt.legend()
filename = os.path.join(output_dir, "encrypt_time_decrypt_time.png")
plt.savefig(filename, dpi=300, bbox_inches="tight")
# plt.show()

# deviation between encrypting and decrypting for each record
records['deviation'] = records['encrypt_time'] - records['decrypt_time']
mean_deviation = records['deviation'].mean()
total_deviation = records['deviation'].sum()
print(f"Mean Deviation: {mean_deviation:.2f} ms")
# print(f"Total Deviation: {total_deviation:.2f} ms")


#total time for each record
records['total_time'] = (records['build_tree_time'] +
                         records['hash_time'] +
                         records['encrypt_time'] +
                         records['decrypt_time'])

# percentage of decrypt time
records['decrypt_percentage'] = (records['decrypt_time'] / records['total_time']) * 100
mean_decrypt_percentage = records['decrypt_percentage'].mean()

print(f"Mean decrypt percentage: {mean_decrypt_percentage:.2f}%")
