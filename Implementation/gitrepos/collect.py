import os
import shutil
from optparse import OptionParser

def get_sourcefile(software):
    src = software + '_git'
    
    cnt = 0
    dst = '../../../joern-0.3.1/testCode/'
    '''
    for p in Path(src).iterdir():
        for s in p.rglob('*.c'):
            #print(s)
            #print(type(s))
            cnt += 1
            shutil.copy(s, dst)
        #for n in p.rglob('*.h'):
            #cnt += 1
    '''
    for root, dirs, files in os.walk(src):
        for f in files:
            if(f[-2:] == '.c'):
                s = os.path.join(root, f)
                shutil.copy(s, dst)

def get_clearfile():
    #res_file = ['mem.c', 'mathematics.c', 'rational.c', 'intfloat_readwrite.c', 'log.c', 'riff.c', 'isom.c', 'matroska.c', 'metadata.c', 'mpeg4audio.c', 'avstring.c', 'lzo.c']
    res_file = ['matroskadec.c', 'lzo.c', 'mem.c', 'aviobuf.c']
    sourcefile = './sourcefile'
    dst = './clearfile'
    for cfile in os.listdir(sourcefile):
        if(cfile in res_file):
            shutil.copy(sourcefile + '/' + cfile, dst)

parser = OptionParser()
(options, args) = parser.parse_args()
if(len(args) != 1):
    print('Missing parameters!')
else:
    get_sourcefile(args[0])

#os.chdir('../../../joern-0.3.1')
#os.system('./joern testCode')
#get_clearfile()
