# fdh-secops-data-pm-analytics
FDH and OS Query analytics source code, input files and output for sharing.

Contains no PII.

# Folder Breakdown

## Code

Directory of two python files; each driven with respective .yml files.
Will update usage at some point.

## 
Input

###
Zipped CSV files provided by Kyle Claridge containing approx 3 days of os query data used for investigations.
Source input to analytics scripts, used to generate JSON files in output folder

##
Output

###
JSON FDH and OS Query analytics output.
Will be updated iteratively based on feedback and bug fixes

## 
Known Issues

###
A percentage of 'OS' SQL queries are not parsed properly. Script tracks errors. Need to publish error rates to respective JSON output.

##
Repo TODO

* Improve code documentation
* Provide usage documentation
* Add script design
* Summarize script shortcomings
* Work to improve SQL query parsing to reduce error rates
