import re

ts1 = "$created-by0 (created:$threat-actor, creator:$identity0) isa created-by;\n \n $object-marking1 (marked:$threat-actor, marking:$marking-definition01) isa object-marking;"

ts2 = '$threat-actor isa threat-actor, has stix-id "threat-actor--8b6297fe-cae7-47c6-9256-5584b417849c";'

def get_local_relns(dep_insert):
    m = re.findall(r"(\$[a-z\-0-9]+)\s+(.+)?isa\s+", dep_insert,re.MULTILINE)
    #logger.info(f'local 1 -> {m}')
    if m:
        #logger.info(f'local -> {m}')
        return [g[0] for g in m]
    else:
        return []


def get_object_variable(core_ql):
    m = re.findall(r"[a-z\-\_]+;$",core_ql,re.MULTILINE)
    return m

# if this file is run directly, then start here
if __name__ == '__main__':
    logger.info("ts1=================")
    get_local_relns(ts2)
    logger.info("ts2====================")
    get_object_variable(ts1)