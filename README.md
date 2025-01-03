# fdh-secops-data-pm-analytics
FDH and OS Query analytics source code, input files and output for sharing.

Contains no PII.

# Folder Breakdown

## Code

Directory of two python files; each driven with respective .yml files.
Will update usage at some point.

## Input

Zipped CSV files provided by Kyle Claridge containing approx 3 days of os query data used for investigations.
Source input to analytics scripts, used to generate JSON files in output folder

## Output

JSON FDH and OS Query analytics output.
Will be updated iteratively based on feedback and bug fixes

### OS Query JSON Structure

```json
{
  "osquery_summary": {
      "os_query_data_analysis_stats": [
          # Meta data on data analyzed
       ],
      "os_query_input_query_summary": [
          # Very large os query object summary list  
       ]
      "os_query_table_analysis_summary": [
          # Usage summary of tables used in the input data set
          # Also break down of tables by queries
       ]
      "os_query_attribute_analysis_summary": [
          # Break down of 4 groups of attributes based on confidence of data returned 
          # Valid attributes
          # Valid attributes that were parsed to include SQL (SQL parsing not strict enough)
          # Invalid attributes: SQL parsing returned non-attribute values
          # Unique_attribute_list: full list of unique attributes  present in queries
       ]



   }
}
```


##  Known Issues

* A percentage of 'OS' SQL queries are not parsed properly. Script tracks errors. Need to publish error rates to respective JSON output.

## Repo TODO

* Update repo to summarize analytics goals
* Improve code documentation
* Provide usage documentation
* Add script design
* Summarize script shortcomings
* Work to improve SQL query parsing to reduce error rates
