# fdh-secops-data-pm-analytics
FDH and OS Query analytics source code, input files and output for sharing.

Contains no PII.

<ins>__January 3, 2025: Still work-in-progress. Deliverable not complete__</ins>

# Folder Breakdown

## Code

Directory of two python files; each driven with respective .yml files.
Will update usage at some point.

## Input

### OS Query Data
Zipped CSV files provided by Kyle Claridge containing approx 3 days of os query data used for investigations.
Source input to analytics scripts, used to generate JSON files in output folder

### FDH Schema
Copy of _symlink_xdr_ext_data_view_definition.json_ from here: https://github.com/sophos-internal/cld.data-tools.xdr-schema-util/blob/master/output/views/symlink_xdr_ext_data_view_definition.json

Set of events and their attributes used to compare against OS Query attribute data

## Output

JSON FDH and OS Query analytics output.
Will be updated iteratively based on feedback and bug fixes


### FDH Analytics JSON Structure

```json
{
    "fdh_summary": {
        # List of FDH event types
        # Attribute counts by FDH event types 
     },
    "fdh_attributes": [
        # List of each FDH attribute that includes
        # Uniqueness
        # Which event they arefound in
        # Type
     ]
    "fdh_raw_attributes": [
        # List of fdh event types and their set of attributes with type
     ]
}
```


### OS Query Analytics JSON Structure

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
