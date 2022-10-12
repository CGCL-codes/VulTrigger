import os

init_path = '/home/SySeVR/Implementation/source2slice/pre_data/test'
base_lz = ''
for cve in os.listdir(init_path):
    cve_path = init_path + '/' + cve
    print(os.listdir(cve_path))
    for f in os.listdir(cve_path):
        if('.diff' in f):
            base_lz = f
            print(base_lz)
            break

    for f in os.listdir(cve_path):
        rs = f.split('_')
        print(rs)
        tmp_f = f
        if('new.c' in rs[-1] or 'NEW.c' in rs[-1]):
            new_f = base_lz.replace('.diff', '_NEW.c')
            os.system('mv ' + cve_path + '/' + tmp_f + ' ' + cve_path + '/' + new_f)
            print(new_f)
        if('old.c' in rs[-1] or 'OLD.c' in rs[-1]):
            new_f = base_lz.replace('.diff', '_OLD.c')
            os.system('mv ' + cve_path + '/' + tmp_f + ' ' + cve_path + '/' + new_f)
            print(new_f)
