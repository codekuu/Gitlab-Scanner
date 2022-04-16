import csv


def write_csv(data, filename):
    """write data to csv file"""
    headers = data[0].keys()
    with open(filename, "w") as outfile:
        writer = csv.DictWriter(outfile, headers)
        writer.writeheader()
        writer.writerows(data)
