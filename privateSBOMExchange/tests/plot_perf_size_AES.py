import json
import os
import configparser
import matplotlib.pyplot as plt
import seaborn as sns
import pandas


config = configparser.ConfigParser()
config.read('config/config.ini')
 
# results_dir = config['DEFAULT']['results']
# results_dir = "/Users/okafor1/Documents/RA/Fall_2024/SBOMCtl/privateSBOMExchange/output"
results_dir = config['DEFAULT']['results']
print(results_dir)

read_from = os.path.join(results_dir, "performance_intellectual_property_policy.json")

performance_data = []  
with open(read_from, 'r') as file:
    for line in file:
        performance_data.append(json.loads(line.strip())) 

records = pandas.DataFrame.from_records(performance_data)


# normalize values to MB and 10's of thousands of nodes
records['file_size'] = records['file_size'].apply(lambda x: int(x/1e6))
records['encrypted_tree_storage'] = records['encrypted_tree_storage'].apply(lambda x: int(x/1e6))
# records['encrypt_time'] = records['encrypt_time'].apply(lambda x: int(x/60))
# records['decrypt_time'] = records['decrypt_time'].apply(lambda x: int(x/60))
records['tree_nodes_count'] = records['tree_nodes_count'].apply(lambda x: int(x/1e4))


# filter out excessively large nodes (let's keep it under 30 MB)
# records = records.loc[records['file_size'] < 30]
#import pdb; pdb.set_trace()

# filter out measurements that do not have enough occurrences (more than 5 here)
OCCURRENCE_MIN = 5
_filter = records.file_size.value_counts()
records = records[records.file_size.isin(_filter.index[_filter.gt(OCCURRENCE_MIN)])]


total_records = len(records)

# sns.set_style("whitegrid")
plt.figure(figsize=(12, 8))


# # Build Tree Time vs File Size
# plt.subplot(3, 3, 1)
# sns.violinplot(data=records, y='build_tree_time', x='file_size', cut=0, palette="tab20")
# # sns.scatterplot(x=file_sizes, y=build_times)
# plt.xlabel(f"File Size (MB)")
# plt.ylabel(f"Build Tree Time (s)")
# plt.title("Build Tree Time vs File Size")

# # Hash Time vs Node Count
# plt.subplot(3, 3, 4)
# sns.violinplot(data=records, y='hash_time', x='tree_nodes_count', cut=0, palette="tab20")
# # sns.scatterplot(x=tree_nodes_count, y=hash_times)
# plt.xlabel("Node Count (hundreds of thousands)")
# plt.ylabel("Hash Time (s)")
# plt.xticks(ticks=plt.xticks()[0][::4])
# plt.title("Hash Time vs Node Count")

# Encrypt vs File Size
plt.subplot(3, 3, 1)
sns.violinplot(data=records, y='encrypt_time', x='file_size', cut=0, palette="tab20")
# sns.boxplot(data=records, y='encrypt_time', x='file_size',showfliers=True, palette="tab20")
# sns.boxenplot(data=records, y='encrypt_time', x='file_size',showfliers=True, palette="tab20")
plt.xlabel("File Size (MB)")
plt.ylabel("Encrypt Time (s)")
# plt.title("Encrypt Time vs File Size ({} records)".format(total_records))

##Decrypt Time vs File Size
plt.subplot(3, 3, 2)
# sns.boxplot(data=records, y='decrypt_time', x='file_size', showfliers=True, palette="tab20")
# sns.boxenplot(data=records, y='decrypt_time', x='file_size', showfliers=True, palette="tab20")
sns.violinplot(data=records, y='decrypt_time', x='file_size', cut=0, palette="tab20")
plt.xlabel("File Size (MB)")
plt.ylabel("Decrypt Time (s)")
# plt.title("Decrypt Time vs File Size ({} records)".format(total_records))

##Encrypt Time vs Node Count
plt.subplot(3, 3, 4)
# sns.boxplot(data=records, y='encrypt_time', x='tree_nodes_count', showfliers=True, palette="tab20")
# sns.boxenplot(data=records, y='encrypt_time', x='tree_nodes_count', showfliers=True, palette="tab20")
sns.violinplot(data=records, y='encrypt_time', x='tree_nodes_count', cut=0, palette="tab20")
plt.xlabel("Node Count (hundreds of thousands)")
plt.ylabel("Encrypt Time (s)")
plt.xticks(ticks=plt.xticks()[0][::2])
# plt.title("Encrypt Time vs Node Count ({} records)".format(total_records))

##Decrypt Time vs Node Count
plt.subplot(3, 3, 5)
# sns.boxplot(data=records, y='decrypt_time', x='tree_nodes_count', showfliers=True, palette="tab20")
# sns.boxenplot(data=records, y='decrypt_time', x='tree_nodes_count', showfliers=True, palette="tab20")
sns.violinplot(data=records, y='decrypt_time', x='tree_nodes_count', cut=0, palette="tab20")
plt.xlabel("Node Count (hundreds of thousands)")
plt.ylabel("Decrypt Time (s)")
plt.xticks(ticks=plt.xticks()[0][::2])
# plt.title("Decrypt Time vs Node Count ({} records)".format(total_records))

plt.subplot(3, 3, 3)
# sns.boxplot(data=records, y='tree_nodes_count', x='file_size',showfliers=True, palette="tab20")
# sns.boxenplot(data=records, y='tree_nodes_count', x='file_size', showfliers=True, palette="tab20")
sns.violinplot(data=records, x='file_size', y='tree_nodes_count', cut=0, palette="tab20")
plt.ylabel("Node Count (hundreds of thousands)")
plt.xlabel("File Size (MB)")
# plt.xticks(ticks=plt.xticks()[0][::4])
# plt.title("Node Count vs File Size ({} records)".format(total_records))

plt.subplot(3, 3, 6)
# sns.boxplot(data=records, y='tree_nodes_count', x='file_size',showfliers=True, palette="tab20")
# sns.boxenplot(data=records, y='tree_nodes_count', x='file_size', showfliers=True, palette="tab20")
sns.violinplot(data=records, y='encrypted_tree_storage', x='tree_nodes_count', cut=0, palette="tab20")
plt.xlabel("Node Count (hundreds of thousands)")
plt.ylabel("Encrypted Tree Size (MB)")
# plt.xticks(ticks=plt.xticks()[0][::4])
# plt.title("Node Count vs File Size ({} records)".format(total_records))


plt.tight_layout()
sns.despine()
#plt.show()
plt.savefig(os.path.join(results_dir, "performance_intellectual_property_policy.png"))

