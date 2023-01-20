This folder contains all the code and data needed for the VulTrigger implementation. The purpose of each file is explained below.
The implementation of VulTrigger is mainly divided into three steps. 
1. Identifying Critical Variables. This step needs the `cv_extract.py` file.
2. Generating Program Slices. This step needs the files `get_depen.py`, `get_cfg_relation.py`, `complete_PDG.py`, `access_db_operate.py`, `extract_df2.py`, `general_op2.py`, and `slice_op2.py`.
3. Identifying Vulnerability-Triggering Statements. This step requires all the code in the `./match_sink` folder.

Next, the functions in each file will be introduced.
-  `cv_extract.py`: Preprocess the diff file and identify critical variables. The results are stored in ***../result***.
-  `get_depen.py`: Use ***joern*** to parse the vulnerability function, obtain possible dependency files, and store the results in ***./data/Dependency_Files***.
-  `get_cfg_relation.py`: Use ***joern*** to parse all dependent files, get the CFG graph, and store it in ***./cfg_db/testCode***.
-  `complete_PDG.py`: Use ***joern*** to parse all dependent files, get the PDG graph, and store it in ***./pdg_db/testCode***.
- `access_db_operate.py`: Use ***joern*** to parse all dependent files, get the call graph, and store it in ***./dict_call2cfgNodeID_funcID/testCode***.
- `extract_df2.py`: Start slicing from the modified lines in the diff file. It should be noted that we use function call graphs and PDG graphs to obtain data flow information across functions. The results are stored in ***./results***.
- `general_op2.py`: Some general functions when generating *cfg graph*, *pdg graph* or *call graph*.
- `slice_op2.py`: Some general functions when generating program slices.
- `config.json`: The configuration file. Please modify it according to your own directory before executing.
- `./match_sink/match_sink.py`: Identify vulnerability-triggering statements according to the CWE. You should execute the following command:

	`python3 match_sink.py [cve id] [software]`

	Take CVE-2011-2929 as an example, the command is as follows:

	`python3 match_sink.py CVE-2011-2929 ffmpeg`
- `all_data.xlsx`: This file shows the patch function information for each CVE.
- `pre_data/process_name.py`: Normalize the format of all the data to be tested in the ***./pre_data/test*** folder.
- `./gitrepos`: This foler stores the required software repository source code. The naming format is `[software_git]`, e.g., `ffmpeg_git`. If you want to analyze the CVE of a certain software, please make sure that the repository source code of the software exists in this directory.
- `./pre_data`: This folder stores the data to be tested.
- `./data`: This folder stores the diff file, vulnerability file and non-vulnerability file for this test. The ***./data/Dependency_Files*** folder stores the dependency files of each CVE according to the software classification.
- `./cv_result`: This folder stores the results of extracting critical variables.
- `./slice_logs`: This folder stores the log files during the slicing process. If you encounter errors during the slicing process, you can read the files in this folder for specific information.
- `./testCode`: This folder stores the .c files needed in the process of ***Generating Program Slices***.

