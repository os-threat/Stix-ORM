import csv
import os
import glob
import csv

heading_align = [
    ":--------------------|",
    ":--------------------------------:|",
    ":------------------:|",
    ":------------------------:|",
    ":-------------:|"
]

input_docs = [
    {
        "dir": "sdo",
        "file": "sdo.csv",
        "obj_type": "Domain"
    },
    {
        "dir": "sco",
        "file": "sco.csv",
        "obj_type": "Cyber Obervable"
    }
]


def delete_existing_markdown(dir):
    cwd = os.getcwd()
    del_dir = cwd + "\\" + dir
    del_pattern = del_dir + "\\" + "*.md"
    fileList = glob.glob(del_pattern)
    print(f'fileList is {fileList}')
    for filePath in fileList:
        try:
            os.remove(filePath)
        except:
            print("Error while deleting file : " ,filePath)
    return del_dir


def generate_md(dir, fields, row, obj_type):
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


def gen_docs(docs):
    for doc_set in docs:
        # Get details for each set of documents
        dir = doc_set["dir"]
        doc_file = doc_set["file"]
        obj_type = doc_set["obj_type"]
        # delete existing markdown documents
        full_doc_dir = delete_existing_markdown(dir)
        # generate new markdown docs in the target directory
        if full_doc_dir != "":
            file_path = full_doc_dir + "\\" + doc_file
            rows=[]
            with open(file_path, 'r') as csvfile:
                # creating a csv reader object
                csvreader = csv.reader(csvfile)

                # extracting field names through first row
                fields = next(csvreader)

                # extracting each data row one by one
                for row in csvreader:
                    generate_md(full_doc_dir, fields, row, obj_type)
                    rows.append(row)

                # get total number of rows
                print("Total no. of rows: %d" % (csvreader.line_num))


# if this file is run directly, then start here
if __name__ == '__main__':
    gen_docs(input_docs)