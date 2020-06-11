import binwalk
import subprocess
import shlex
import sys


file_name = sys.argv[1]


def dd_file(skip,id,count=None):
    out_file = "data" + str(id)
    if count is None:#Take care of the last segment
        dd_args = f"dd if={file_name} of={out_file} bs=1 skip={skip}"
    else:
        dd_args = f"dd if={file_name} of={out_file} bs=1 skip={skip} count={count}"
    args = shlex.split(dd_args)
    subprocess.run(args)


modules = binwalk.scan(file_name, signature=True,quiet=True)
results = modules[0].results
for i,r in enumerate(results):
    if i!=(len(results)-1):
        print(r.description)
        dd_file(r.offset,i,results[i+1].offset-r.offset)
    else:#take care of the last segment
        print(r.description)
        dd_file(r.offset,i)

