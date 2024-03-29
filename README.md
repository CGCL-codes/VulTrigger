# On the Effectiveness of Function-Level Vulnerability Detectors for Inter-Procedural Vulnerabilities #

We propose a tool, dubbed VulTrigger, for identifying vulnerability-triggering statements across functions and investigating the effectiveness of function-level vulnerability detectors in detecting inter-procedural vulnerabilities.  For this purpose, we built the first Inter-Procedural Vulnerability Dataset (InterPVD) for C/C++ open-source software. We find: 
1. inter-procedural vulnerabilities are prevalent with an average of 2.8 inter-procedural layers;
2. detecting inter-procedural vulnerabilities is significantly more challenging than detecting intra-procedural vulnerabilities for function-level vulnerability detectors.

##  Requirements ##
To use VulTrigger, you need:
1. python 2.x, 3.
2. joern 0.3.1 (jdk 1.7)
3. neo4j 2.1.5

## Step Instructions ##
You can run it step-by-step for a better understanding of the VulTrigger tool, or use the script all_data.py to more efficiently get results from multiple CVEs.

**(1) Step-by-step**
1. Enter the software repository and switch it to the corresponding version.
	Take CVE-2013-0852 as an example:
	CVE-2013-0852's hash is c0d68be555f5858703383040e04fcd6529777061, execute in the ./gitrepos/ffmpeg_git:
	`git checkout c0d68be555f5858703383040e04fcd6529777061`
2. Stop neo4j service and delete the .***joernIndex*** in the joern installation directory.
3. Execute the file `./gitrepos/collect.py`.
4. Restart neo4j server.
5. Execute the file `get_depen.py [software]`.
6. Copy dependent files to `[joern installation directory]/testCode`.
7. Execute the command `./joern testCode` in joern installation directory.
8. Modify `config.json`.
9. Put the relevant files of the CVE to be tested in the ./data/C-Diffs, ./data/C-Non_Vulnerable_Files, ./data/C-Vulnerable_Files folders.
10. Execute the file `cv_extract.py`. 
11. Put the generated dependency files in the ***./testCode*** folder.
12. Execute the file `get_cfg_relation.py`.
13. Execute the file `complete_PDG.py`.
14. Execute the file `access_db_operate.py`.
15. Execute the file `extract_df2.py`.
16. Execute the file `match_sink.py [cwe] [software]`. 

**(2) Automated method**
1. Put all the CVEs to be detected in the ***./pre_data/test*** directory. It should be noted that they must be CVEs of the same software.
2. Modify `config.json`.
3. Execute the file `all_data_test.py [software]`. 
4. Execute the file `match_sink.py [cwe] [software]`. 

***We provide the environments and test code of other vulnerability detection tools we evaluate, including three open-sourced tools (i.e., Flawfinder, Infer, and CodeQL) and five function-level vulnerability detectors (i.e., VulBERTa, LineVul, Devign, ReVeal, and VulCNN) in the form of docker images. We publish them on Docker Hub and the link is available at https://hub.docker.com/r/vultrigger/models_tools_env/tags.***
## Support or Contact
VulTrigger is developed at SCTS&CGCL Lab (http://grid.hust.edu.cn) by Zhen Li, Ning Wang, Deqing Zou, Yating Li, Ruqian Zhang, Shouhuai Xu, Chao Zhang, and Hai Jin. For any questions, please contact Zhen Li (zh_li@hust.edu.cn) , Ning Wang (wangn@hust.edu.cn) , Deqing Zou (deqingzou@hust.edu.cn) , Yating Li (liyating20210228@163.com) , Ruqian Zhang (ruqianzhang@hust.edu.cn) , Shouhuai Xu (sxu@uccs.edu) , Chao Zhang (chaoz@tsinghua.edu.cn) and Hai Jin (hjin@hust.edu.cn).

Copyright (C) 2023, [STCS & CGCL](http://grid.hust.edu.cn/) and [Huazhong University of Science and Technology](http://www.hust.edu.cn/).
