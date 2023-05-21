import csv
import os
import glob
import csv
import json

from stix.module.definitions.stix21 import stix_models
from stix.module.definitions.attack import attack_models
from stix.module.definitions.os_threat import os_threat_models
from stix.module.definitions.cacao import cacao_models
from stix.module.definitions.kestrel import kestrel_models

heading_align = [
    ":--------------------|",
    ":--------------------------------:|",
    ":------------------:|",
    ":------------------------:|",
    ":-------------:|"
]

object_docs = [
    {
        "dir": "sdo",
        "protocol": "stix21",
        "file": "sdo.csv",
        "obj_type": "Domain"
    },
    {
        "dir": "sco",
        "protocol": "stix21",
        "file": "sco.csv",
        "obj_type": "Cyber Obervable"
    }
]


object_tables = [
    {
        "title": "OASIS Stix 2.1",
        "protocol": "stix21",
        "objects": stix_models["mappings"]["object_conversion"]
    },
    {
        "title": "Mitre ATT&CK",
        "protocol": "attack",
        "objects": attack_models["mappings"]["object_conversion"]
    }
]
protocols = [
    "stix21",
    "attack"
]

titles = {
    "stix21": "OASIS Stix 2.1",
    "attack": "MITRE ATT&CK",
    "os-threat": "OS-Threat Custom",
    "sdo": "Domain Object's Types",
    "sco": "Cyber Observable Object Types",
    "sro": "Relationship Object Types",
    "sub": "Sub-Object Types"
}
object_types = [
    "sdo",
    "sco",
    "sro",
    "sub"
]

def gen_tables(obj_tables):
    bucket = {}
    bucket["stix21"] = {}
    bucket["attack"] = {}
    bucket["stix21"]["sdo"] = []
    bucket["stix21"]["sro"] = []
    bucket["stix21"]["sco"] = []
    bucket["stix21"]["sub"] = []
    bucket["attack"]["sdo"] = []
    bucket["attack"]["sro"] = []
    bucket["attack"]["sco"] = []
    bucket["attack"]["sub"] = []
    for table in obj_tables:
        obj_set = table["objects"]
        protocol = table["protocol"]
        layer = {}
        for obj in obj_set:
            obj_type = obj["object"]
            bucket[protocol][obj_type].append(obj)

    return bucket


def print_normal_rows(rel_dir, size, outfile, bucket_list, icon_dir, md_dir):
    for obj in bucket_list:
        detail_string = ""
        icon = obj["icon"]
        name = obj["typeql"]
        docs = obj["doc_url"]
        summary = obj["summary"]
        #print(f"---- summary -> {summary}")
        print(f"icon dir -> {icon_dir}, md dir {md_dir}")
        if icon == "":
            icon_name = ""
            icon_dir_name = ""
        else:
            icon_name = name
            icon_dir_name = icon_dir + icon
        if docs == "":
            name_dir = ""
        else:
            name_dir = md_dir + docs

        icon_md = "![" + icon_name + "](" + icon_dir_name + ")"
        name_md = "[" + name + "](" + name_dir + ")"
        detail_string += "| " + icon_md + " | " + name_md + " | " + summary + " |"
        print(detail_string, file=outfile)


def print_summary_rows(rel_dir, size, outfile, bucket_list, icon_dir, md_dir):
    num_objs = len(bucket_list)
    rows = num_objs // size
    remainder = num_objs % size
    rel_path = "protocols/"
    k = 0
    if remainder != 0:
        rows += 1
        filler = size - remainder
    for j in range(rows):
        detail_string = ""
        for i in range(size):
            icon = ""
            name = ""
            docs = ""
            if k < num_objs:
                layer = bucket_list[k]
                icon = layer["icon"]
                name = layer["typeql"]
                docs = layer["doc_url"]

            if icon == "":
                icon_name = ""
                icon_dir_name = ""
            else:
                icon_name = name
                icon_dir_name = icon_dir + icon
            if docs == "":
                name_dir = ""
            else:
                name_dir = md_dir + docs
            icon_md = "![" + icon_name + "](" + icon_dir_name + ")"
            name_md = "[" + name + "](" + name_dir + ")"
            detail_string += "| " + icon_md + " | " + name_md
            k += 1

        detail_string += " |"
        print(detail_string, file=outfile)


def print_summary_tables(rel_dir, outfile, protocol, bucket, size):
    print("In summary tables")
    print(f"reldir 1-> {rel_dir}")

    # Setup Table Headers
    if rel_dir == "./docs":
        rel_dir = "./protocols"
    elif rel_dir == "./docs/protocols":
        rel_dir = "."
    elif rel_dir == "./docs/protocols/stix21":
        rel_dir = "."
    sub_head = ""
    print(f"reldir 2-> {rel_dir}")
    head_string = ""
    under_string = ""
    row_string = ""
    for i in range(size):
        head_string += "| Icon | Object Type "
        under_string += "|:----------:|:-----------"
    if size == 1:
        head_string = "| Icon | Object Type | Description"
        under_string = "|:----------:|:-----------|:-----------"
    head_string += " |"
    under_string += " |"
    print(f"I am ready to process summary tables, size {size}")
    print(f"object types {object_types}")
    for obj_type in object_types:
        print(f"\n###  {titles[obj_type]}\n", file=outfile)
        print(f'obj type {obj_type}, protocol {protocol}, protocols {protocols}')
        if protocol == "all":
            for proto in protocols:
                local_bucket = bucket[proto][obj_type]
                print(f'local bucket length is -> {len(local_bucket)}')
                if len(local_bucket) != 0:
                    md_dir = rel_dir + "/" + proto + "/" + obj_type + "/"
                    icon_dir = rel_dir + "/" + proto + "/icons/"
                    print(f"#### {titles[proto]} \n", file=outfile)
                    print(head_string, file=outfile)
                    print(under_string, file=outfile)
                    if size == 1:
                        print("go down the size==1 route and protocol !=1")
                        print_normal_rows(rel_dir, size, outfile, bucket[proto][obj_type], icon_dir, md_dir)
                    else:
                        print("go down the size!=1 and protocol !=1 route")
                        print_summary_rows(rel_dir, size, outfile, bucket[proto][obj_type], icon_dir, md_dir)
                    print("\n\n", file=outfile)
        else:
            local_bucket = bucket[protocol][obj_type]
            if len(local_bucket) != 0:
                md_dir = rel_dir + "/" + obj_type + "/"
                icon_dir = rel_dir + "/icons/"
                print(f"#### {titles[protocol]} \n", file=outfile)
                print(head_string, file=outfile)
                print(under_string, file=outfile)
                if size == 1:
                    print("go down the size==1 route")
                    print_normal_rows(rel_dir, size, outfile, bucket[protocol][obj_type], icon_dir, md_dir)
                else:
                    print("go down the size!=1 route")
                    print_summary_rows(rel_dir, size, outfile, bucket[protocol][obj_type], icon_dir, md_dir)
                print("\n\n", file=outfile)


def gen_overview_doc(rel_dir, bucket, protocol, size):
    print("generate overview")
    # open up generic overview doc
    md_name = rel_dir + "/" + "overview.md"
    or_mname = rel_dir + "/" + "_orig.md"
    if os.path.exists(md_name):
        os.remove(md_name)
    outfile = open(md_name, "w")
    # insert the top part of the file
    origfile = open(or_mname, "r")
    lines = origfile.readlines()
    for line in lines:
        print(line, file=outfile)
    # now generate overview table
    print("## Total Objects in the System\n\n", file=outfile)
    try:
        print_summary_tables(rel_dir, outfile, protocol, bucket, size)
    except:
        print("ERROR IN OBJECT Table GENERATION")
    # close the overview markdown file
    outfile.close()


def configure_overview_table_docs(obj_tables):
    print("starting to process the list of objects")
    bucket = gen_tables(obj_tables)
    # Setup Library Overview Document
    rel_dir = "./docs"
    gen_overview_doc(rel_dir, bucket, "all", 3)
    # Setup Protocol Overview Document
    rel_dir = "./docs/protocols"
    gen_overview_doc(rel_dir, bucket, "all", 1)
    # Setup Library Overview Document
    rel_dir = "./docs/protocols/stix21"
    gen_overview_doc(rel_dir, bucket, "stix21", 1)



def delete_existing_markdown(dir):
    cwd = os.getcwd()
    del_dir = cwd + "\\" + dir
    del_pattern = del_dir + "\\" + "*.md"
    fileList = glob.glob(del_pattern)
    print(f'delete fileList is {fileList}')
    for filePath in fileList:
        try:
            os.remove(filePath)
        except:
            print("Error while deleting file : " ,filePath)
    return del_dir


def generate_object_doc(dir, fields, row, obj_type):
    image = row[0]
    table = row[1]
    stix_type = row[2]
    obj = row[3]
    para1 = row[4]
    para2 = row[5]
    url = row[6]
    json_example = row[7]
    tql_ins = row[8]
    tql_match = row[9]
    py_match = row[10]
    md_name = dir + "\\" + obj + ".md"
    outfile = open(md_name, "w")
    # 1. Setup Page title
    print(f'# {obj} {obj_type} Object\n', file=outfile)
    print(f'**Stix and TypeQL Object Type:**  `{stix_type}`\n', file=outfile)
    # 2. Setup Overview paragraphs
    print(f'{para1}\n', file=outfile)
    if para2 != "":
        print(f'{para2}\n', file=outfile)
    print(f'[Reference in Stix2.1 Standard]({url})', file=outfile)
    # 3. Setup Table
    print(f'## Stix 2.1 Properties Converted to TypeQL', file=outfile)
    print(f'Mapping of the Stix Attack Pattern Properties to TypeDB\n', file=outfile)
    table_name = dir + "\\csv\\" + table
    rows = []
    with open(table_name, 'r') as csvfile:
        # creating a csv reader object
        csvreader = csv.reader(csvfile)

        # extracting field names through first row
        field_list = next(csvreader)
        fields = "| "
        for field in field_list:
            fields += field + " |"
        heading = "|"
        for head in heading_align:
            heading += head
        print(f'{fields}', file=outfile)
        print(f'{heading}', file=outfile)
        # extracting each data row one by one
        for row in csvreader:
            cols = "| "
            for col in row:
                cols += col + " |"
            print(f'{cols}', file=outfile)
    # 4. Setup JSON Section
    print(f'\n## The Example {obj} in JSON', file=outfile)
    print(f'The original JSON, accessible in the Python environment', file=outfile)
    print(f'```json\n{json_example}\n```\n', file=outfile)
    # 5. Setup TypeQL Insert Section
    print(f'\n## Inserting the Example {obj} in TypeQL', file=outfile)
    print(f'The TypeQL insert statement', file=outfile)
    print(f'```typeql\n{tql_ins}\n```\n', file=outfile)
    # 6. Setup TypeQL Match Section
    print(f'## Retrieving the Example {obj} in TypeQL', file=outfile)
    print(f'The typeQL match statement\n', file=outfile)
    print(f'```typeql\n{tql_match}\n```\n', file=outfile)
    # 7. Setup Force Graph Image Section
    print(f'\nwill retrieve the example attack-pattern object in Vaticle Studio', file=outfile)
    imagefile = "./img/"+image
    print(f'![{obj} Example]({imagefile})', file=outfile)
    # 8. Setup Python Match Section
    print(f'\n## Retrieving the Example {obj}  in Python', file=outfile)
    print(f'The Python retrieval statement\n', file=outfile)
    print(f'```python\n{py_match}\n```\n', file=outfile)
    # 9. Close the File
    outfile.close()
    return


def gen_obj_docs(docs):
    # generate object docs
    for doc_set in docs:
        # Get details for each set of documents
        sub_dir = doc_set["dir"]
        doc_file = doc_set["file"]
        obj_type = doc_set["obj_type"]
        prot_type = doc_set["protocol"]
        # delete existing markdown documents
        rel_path = "protocols/" +prot_type +"/" + sub_dir
        full_doc_dir = delete_existing_markdown(rel_path)
        # generate new markdown docs in the target directory
        if full_doc_dir != "":
            file_path = full_doc_dir + "/" + doc_file
            rows=[]
            with open(file_path, 'r') as csvfile:
                # creating a csv reader object
                csvreader = csv.reader(csvfile)

                # extracting field names through first row
                fields = next(csvreader)

                # extracting each data row one by one
                for row in csvreader:
                    generate_object_doc(full_doc_dir, fields, row, obj_type)
                    rows.append(row)

                # get total number of rows
                print("Total no. of rows: %d" % (csvreader.line_num))


# if this file is run directly, then start here
if __name__ == '__main__':
    #gen_obj_docs(object_docs)
    configure_overview_table_docs(object_tables)