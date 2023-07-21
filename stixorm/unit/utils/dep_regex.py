import sys,os,json
import re

def check_status(key:str,status:dict):
    if key in status:
        return status[key]
    else:
        return False

def set_status(key:str,status:dict):

    status[key]=True

    for kk in status.keys():
        if key != kk: status[kk]=False


if __name__ == '__main__':

    with open('example.txt','r') as file:
        text = file.read()

        status = {}
        for no,line in enumerate(text.split('\n')):
            if line.startswith('core_ql'):
                print(f'Core found at {no}')
                # check rest of line
                query = line[line.index('>')+1:].strip()
                set_status('core_ql',status)

            elif check_status('core_ql',status):
                query = line.strip()

            if line.startswith('indep_ql'):
                print(f'Indep found at {no}')
                # check rest of line
                query = line[line.index('>')+1:].strip()
                if len(query)>0:
                    m = re.search(r"(\$[a-z\-\_]+)\s+isa\s+", query)
                    if m:
                        first_word = m.groups()[0]
                        print(f'Found first {first_word}')

                set_status('indep_ql',status)
            elif check_status('indep_ql',status):
                query = line.strip()
                if len(query)>0:
                    m = re.search(r"(\$[a-z\-\_]+)\s+isa\s+", query)
                    if m:
                        first_word = m.groups()[0]
                        print(f'Found first {first_word}')

            if line.startswith('dep_match'):
                print(f'Dep match found at {no}')
                # check rest of line
                query = line[line.index('>')+1:].strip()

                set_status('dep_match',status)
            elif check_status('dep_match',status):
                query = line.strip()

            if line.startswith('dep_insert ->'):
                print(f'Dep Insert found at {no}')
                # check rest of line
                query = line[line.index('>')+1:].strip()
                if len(query)>0:
                    m = re.search(r"[a-z\-\_]+;$",query)
                    last_word = m.group(0)
                    print(f'Found last {last_word}')

                set_status('dep_insert',status)
            elif check_status('dep_insert',status):
                query = line.strip()
                if len(query)>0:
                    m = re.search(r"[a-z\-\_]+;$",query)
                    if m:
                        last_word = m.group(0)
                        print(f'Found last {last_word}')







