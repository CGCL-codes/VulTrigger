This folder contains all the code and data needed for the VulTrigger implementation. The purpose of each file is explained below.
The implementation of VulTrigger is mainly divided into five steps. Among them, steps 1, 2, and 4 are automated.
1. Identifying Critical Variables. This step needs the `cv_extract.py` file.
2. Generating Program Slices. This step needs the files `get_depen.py`, `get_cfg_relation.py`, `complete_PDG.py`, `access_db_operate.py`, `extract_df2.py`, `general_op2.py`, and `slice_op2.py`.
4. Generating Characteristics.
5. Identifying Vulnerability-Triggering Statements. This step requires all the code in the `./match_sink` folder.
6. Manually Checking and Updating Characteristics.

Next, the functions in each file will be introduced.
-  `cv_extract.py`: Preprocess the diff file and identify critical variables. The results are stored in ***../result***.
-  `get_depen.py`: Use ***joern*** to parse the vulnerability function, obtain possible dependency files, and store the results in ***./data/Dependency_Files***.
-  `get_cfg_relation.py`: Use ***joern*** to parse all dependent files, get the CFG graph, and store it in ***./cfg_db/testCode***.
-  `complete_PDG.py`: Use ***joern*** to parse all dependent files, get the PDG graph, and store it in ***./pdg_db/testCode***.
- `access_db_operate.py`: Use ***joern*** to parse all dependent files, get the call graph, and store it in ***./dict_call2cfgNodeID_funcID/testCode***.
- `extract_df2.py`: Start slicing from the modified lines in the diff file. It should be noted that we use function call graphs and PDG graphs to obtain data flow information across functions. The results are stored in ***./results***.
- `general_op2.py`: Some general functions when generating *cfg graph*、*pdg graph* or *call graph*.
- `slice_op2.py`: Some general functions when generating program slices.
- `config.json`: The configuration file. Please modify it according to your own directory before executing.
- `./match_sink/match_sink.py`: Identify vulnerability-triggering statements according to different CWE types. The inputs are the CWE and the path of vulnerability file. An example is as follows:
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
- `./cv_result`: This folder stores the results of extracting critical variables.
- `./slice_logs`: This folder stores the log files during the slicing process. If you encounter errors during the slicing process, you can read the files in this folder for specific information.
- `./testCode`: Store the .c files needed in process of ***Generating Program Slices***.

