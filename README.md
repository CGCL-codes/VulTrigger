# Towards Understanding and Identifying Cross-Function Vulnerabilities #
We present the first study on characterizing cross-function vulnerabilities and propose VulTrigger for identifying vulnerability-triggering statements. For this purpose, we build the first Cross-Function Vulnerability Dataset (CFVD) for C/C++ open-source software. We find: 
1. the vulnerability type often determines the type of vulnerability-triggering statements, meaning that vulnerability type can be leveraged to identify vulnerability-triggering statements;
2. cross-function vulnerabilities are prevalent with 2.8 cross-function layers on average.

##  Requirements ##
1. python 2.x
2. python 3.x
3. joern 0.3.1 (jdk 1.7)
4. neo4j 2.1.5

## Step Instructions ##
You can run it step-by-step for a better understanding of the tool, or use the script all_data.py to more efficiently get results from multiple CVEs.

**(1) Step-by-step**
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

**(2) Automated method**
1. Put all the CVEs to be detected in the ***./pre_data/test*** directory. It should be noted that they must be CVEs of the same software.
2. Modify `config.json`.
3. Execute the file `all_data_test.py [software]`. 
4. Execute the file `match_sink.py [cwe] [path of vulnerability file] [path of slice file] [path of diff file]` 
