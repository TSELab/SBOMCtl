import json
import os
import configparser
import matplotlib.pyplot as plt
import seaborn as sns
import pandas

config = configparser.ConfigParser()
config.read('config/config.ini')
 
results_dir = config['DEFAULT']['results']

read_from = os.path.join(results_dir, "performance.json")

performance_data = []  
with open(read_from, 'r') as file:
    for line in file:
        performance_data.append(json.loads(line.strip())) 

records = pandas.DataFrame.from_records(performance_data)

# normalize values to MB and 10's of thousands of nodes
records['file_size'] = records['file_size'].apply(lambda x: int(x/1e6))
records['tree_nodes_count'] = records['tree_nodes_count'].apply(lambda x: int(x/1e4))


# filter out excessively large nodes (let's keep it under 30 MB)
#records = records.loc[records['file_size'] < 30]
#import pdb; pdb.set_trace()

# filter out measurements that do not have enough occurrences (more than 5 here)
OCCURRENCE_MIN = 5
_filter = records.file_size.value_counts()
records = records[records.file_size.isin(_filter.index[_filter.gt(OCCURRENCE_MIN)])]

total_records = len(records)

plt.figure(figsize=(12, 8))

# Encrypt & Decrypt Time vs File Size
plt.subplot(2, 2, 1)
sns.violinplot(data=records, y='encrypt_time', x='file_size', cut=0)
plt.xlabel("File Size (MB)")
plt.ylabel("Time (s)")
plt.title("Encrypt Time vs File Size ({} records)".format(total_records))


plt.subplot(2, 2, 2)
#sns.boxenplot(data=records, y='decrypt_time', x='file_size', showfliers=False)
sns.violinplot(data=records, y='decrypt_time', x='file_size', cut=0)
plt.xlabel("File Size (MB)")
plt.ylabel("Time (s)")
plt.title("Decrypt Time vs File Size ({} records)".format(total_records))

##Encrypt & Decrypt Time vs File Size
plt.subplot(2, 2, 4)
#sns.boxenplot(data=records, y='encrypt_time', x='tree_nodes_count', showfliers=False)
sns.violinplot(data=records, y='encrypt_time', x='tree_nodes_count', cut=0)
plt.xlabel("Node Count (hundreds of thousands)")
plt.ylabel("Time (s)")
plt.title("Encrypt Time vs Node Count ({} records)".format(total_records))


plt.subplot(2, 2, 3)
#sns.boxenplot(data=records, y='decrypt_time', x='tree_nodes_count', showfliers=False)
sns.violinplot(data=records, y='decrypt_time', x='tree_nodes_count', cut=0)
plt.xlabel("Node Count (hundreds of thousands)")
plt.ylabel("Time (s)")
plt.title("Decrypt Time vs Node Count ({} records)".format(total_records))


plt.tight_layout()
sns.despine()
#plt.show()
plt.savefig(os.path.join(results_dir, "performance.png"))

