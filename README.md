## VulTrigger: Identifying Vulnerability-Triggering Statements of a Given Vulnerability ##

### 1. Directory structure and instructions ###
**(1) ./data folder：**
This folder contains 704 CVEs data required by the paper, including patch files, vulnerability files and non-vulnerability files for each CVE.

**(2) ./doc folder：**
The file `CFVD.xlsx` is the Cross-Function Vulnerability Dataset (CFVD) for C/C++ open-source software we built. The dataset involves 704 CVE vulnerabilities, each of which is labeled with its patch statements, its vulnerability-triggering statements, being cross-function or not, the type of cross-function vulnerability, and the se- quence of functions starting from the vulnerable function to the vulnerability-triggering function, etc.

**(3) ./Implementation folder**
This folder contains all the code and data needed for the VulTrigger implementation. The purpose of each file is explained below.
The implementation of VulTrigger is mainly divided into five steps. Among them, steps 1, 2, and 4 need to be automated.
1. Identifying Critical Variables. This step needs file `cv_extract.py`
2. Generating Program Slices. This step need files `get_depen.py`, `get_cfg_relation.py`, `complete_PDG.py`, `access_db_operate.py`, `extract_df2.py`, `general_op2.py`, `slice_op2.py`
4. Generating Characteristics
5. Identifying Vulnerability-Triggering Statements. This step requires all the code in the `./match_sink` folder.
6. Manually Checking and Updating Characteristics

Next, the function of each file will be introduced.
-  `cv_extract.py`: Preprocess the diff file and identifying Critical Variables. The results is stored in ***../result***
-  `get_depen.py`: Use ***joern*** to parse the vulnerability function, obtain possible dependency files, and store the results in ***./data/Dependency_Files***
-  `get_cfg_relation.py`: Use ***joern*** to parse all dependent files, get the CFG graph and store it in ***./cfg_db/testCode***
-  `complete_PDG.py`: Use ***joern*** to parse all dependent files, get the PDG graph and store it in ***./pdg_db/testCode***
- `access_db_operate.py`: Use ***joern*** to parse all dependent files, get the Call graph and store it in ***./dict_call2cfgNodeID_funcID/testCode***
- `extract_df2.py`: Start slicing from the modified lines in diff file. It should be noted that we use the function call Graphs and PDG graphs to obtain data flow information across functions. The results is stored in ***./results***
- `general_op2.py`: Some general functions when generating *cfg graph*、*pdg graph* or *call graph*.
- `slice_op2.py`: Some general functions when generating program slices.
- `config.json`: The configuration file. Please modify it according to your own directory before executing.
- `./match_sink/match_sink.py`: According to different CWE types to identify Vulnerability-Triggering Statements. The inputs are CWE and the path of vulnerability file. Example is as follow:
	`python3 match_sink.py [cwe] [path to vulnerability file] [path of slice file] 
	example:
	`python3 match_sink.py 119 ../../dataset/ffmpeg/CVE-2011-3929/CVE-2011-3929_CWE-119_5a396bb3a66a61a68b80f2369d0249729bf85e04_dv.c_1.1_OLD.c/ ./results/ffmpeg/CVE-2011-3929/slices.txt
	If you want to identify Vulnerability-Triggering Statements of CWE-772, CWE-401, CWE-415 or CWE-835, you should execute the following command:
	`python3 match_sink.py [cwe] [path of vulnerability file] [path of slice file] [path of diff file]`
- `all_data.xlsx`: Patch function information for each CVE data.
- `pre_data/process_name.py`: Normalize the format of all the data to be tested in the ***./pre_data/test*** folder.
- `./gitrepos`: Store the required software repository source code, The naming format is `[software_git]` such as `ffmpeg_git`. If you want to analyze the CVE of a certain software, please make sure that the repository source code of the software exists in this directory.
- `./pre_data`: Store the data to be tested.
- `./data`: Store the diff file, vulnerability file and non-vulnerability file for this test. The ***./data/Dependency_Files*** folder stores the dependency files of each CVE according to the software classification.

**(4) ./result folder:**
This folder stores the results of extracting Critical Variables.

### 2. Requirement ###
1. python 2.x
2. python 3.x
3. joern 0.3.1(jdk 1.7)
4. neo4j 2.1.5

### 3. Step Instructions ###
You can run it step-by-step for a better understanding of the tool, or use the script all_data.py to more efficiently get results from multiple CVEs.

**(1) step-by-step**
1. Enter the software repository and switch it to the corresponding version.
	Take CVE-2013-0852 as an example:
	CVE-2013-0852's hash is c0d68be555f5858703383040e04fcd6529777061, execute in the ./gitrepos/ffmpeg_git:
	`git checkout c0d68be555f5858703383040e04fcd6529777061`
2. Stop neo4j service and delete the .***joernIndex*** in the joern installation directory.
3. Execute the file `./gitrepos/collect.py` .
4. Restart neo4j server.
5. Execute the file `get_depen.py [software]`
6. Copy dependent files to `[joern installation directory]/testCode`.
7. Execute the command `./joern testCode` in joern installation directory.
8. Modify `config.json`.
9. Put the relevant files of the CVE to be tested in the ./data/C-Diffs, ./data/C-Non_Vulnerable_Files, ./data/C-Vulnerable_Files folders.
10. Execute the file `cv_extract.py`. 
11. Put the generated dependency files in the ***./testCode*** folder.
12. Execute the file `get_cfg_relation.py`
13. Execute the file `complete_PDG.py`
14. Execute the file `access_db_operate.py`
15. Execute the file `extract_df2.py`
16. Execute the file `match_sink.py [cwe] [path of vulnerability file] [path of slice file] [path of diff file]` `

**(2) automated method**
1. Put all the CVEs to be detected in the ***./pre_data/test*** directory. It should be noted that they must be CVEs of the same software.
2. Modify `config.json`.
3. Execute the file `cv_extract.py`. 
4. Execute the file `all_data_test.py [software]`. 
5. Execute the file `match_sink.py [cwe] [path of vulnerability file] [path of slice file] [path of diff file]` 
