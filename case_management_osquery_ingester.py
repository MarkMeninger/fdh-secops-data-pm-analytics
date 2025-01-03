import ast
import csv
import json
import logging
import pprint
import re
from collections import Counter, defaultdict, OrderedDict
from datetime import datetime

import pandas as pd
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_attribute_names(sql):
    attributes = []

    # Find all SELECT parts before FROM
    select_segments = re.findall(r'SELECT\s+(.*?)\s+FROM', sql, re.DOTALL | re.IGNORECASE)

    for segment in select_segments:
        segments = segment.split(',')
        for item in segments:
            item = item.strip()

            # Handle wildcard '*'
            if '*' in item:
                attributes.append("* (all columns returned)")

            # If 'AS' is present, take the alias name
            elif re.search(r'\bAS\b', item, re.IGNORECASE):
                alias_match = re.search(r'\bAS\s+(\w+)', item, re.IGNORECASE)
                if alias_match:
                    attributes.append(alias_match.group(1))

            # If the segment contains a 'dot', take the part after it
            elif '.' in item:
                attributes.append(item.split('.')[1])

            # Otherwise, it's a direct name and keep it
            else:
                if not re.search(r'STRFTIME|JSON_EXTRACT|datetime\(', item, re.IGNORECASE):
                    attributes.append(item)

    return attributes

def extract_sql_details(sql_query):
    """Extracts details from the SQL query like tables, attributes extracted, and new attributes."""
    table_pattern = re.compile(r'FROM\s+(\w+)', re.IGNORECASE)

    tables_queried = table_pattern.findall(sql_query)
    extracted_attributes = extract_attribute_names(sql_query)

    case_pattern = re.compile(r'CASE\s+WHEN(.+?)END', re.DOTALL)
    case_statements = case_pattern.findall(sql_query)
    new_attributes = [f"description: {case.strip()}" for case in case_statements]

    return tables_queried, extracted_attributes, new_attributes

def read_yaml_config(yaml_path):
    logging.info("Reading YAML configuration file from: %s", yaml_path)
    try:
        with open(yaml_path, 'r') as file:
            config = yaml.safe_load(file)
            logging.info("YAML configuration successfully loaded.")
            return config
    except FileNotFoundError:
        logging.error("YAML configuration file not found.")
        raise
    except yaml.YAMLError as e:
        logging.error("Error parsing YAML file: %s", e)
        raise

def extract_name(query):
    """Extracts the 'name' from the JSON in the 'Query' column."""
    if pd.notnull(query):
        try:
            return json.loads(query).get('name', 'Unnamed')
        except json.JSONDecodeError:
            logging.warning("Invalid JSON format in Query column.")
    return 'Unnamed'

def extract_command(query):
    """Extracts the 'command' from the JSON in the 'Query' column."""
    if pd.notnull(query):
        try:
            command_value = json.loads(query).get('command', 'SQL statement not available').replace('\\n', '\n')
            return f'"{command_value}"'
        except json.JSONDecodeError:
            logging.warning("Invalid JSON format in Query column.")
    return '"SQL statement not available"'

def extract_principal_type(query):
    """Extracts the 'principalType' from the JSON in the 'Query' column."""
    if pd.notnull(query):
        try:
            return json.loads(query).get('principalType', 'Type not available')
        except json.JSONDecodeError:
            logging.warning("Invalid JSON format in Query column.")
    return 'Type not available'

def extract_query_id(query):
    """Extracts the 'queryId' from the JSON in the 'Query' column."""
    if pd.notnull(query):
        try:
            return json.loads(query).get('queryId', 'ID not available')
        except json.JSONDecodeError:
            logging.warning("Invalid JSON format in Query column.")
    return 'ID not available'

def extract_query_type(query):
    """Extracts the 'queryType' from the JSON in the 'Query' column."""
    if pd.notnull(query):
        try:
            return json.loads(query).get('queryType', 'Type not available')
        except json.JSONDecodeError:
            logging.warning("Invalid JSON format in Query column.")
    return 'Type not available'

def extract_query_categories(query):
    """Extracts the 'categories' from the JSON in the 'Query' column."""
    if pd.notnull(query):
        try:
            query_json = json.loads(query)
            categories = query_json.get('categories', [])
            names = [category.get('name', '') for category in categories]
            return ', '.join(names)
        except json.JSONDecodeError:
            logging.warning("Invalid JSON format in Query column.")
    return 'Categories not available'

def append_sorted_attributes_column(df: pd.DataFrame) -> pd.DataFrame:
    if 'unique_osquery_table' not in df.columns or 'unique_osquery_attributes' not in df.columns:
        logging.error("Necessary columns 'unique_osquery_table' or 'unique_osquery_attributes' not found in DataFrame.")
        return df

    df['new_column_name'] = df['unique_osquery_table'].apply(lambda x: '_'.join(x) if isinstance(x, list) else 'unnamed_table')

    df['sorted_attributes'] = df['unique_osquery_attributes'].apply(lambda x: ', '.join(sorted(x)) if isinstance(x, list) else 'no_attributes')

    for index, row in df.iterrows():
        column_name = row['new_column_name']
        if column_name not in df.columns:
            df[column_name] = None
        df.at[index, column_name] = row['sorted_attributes']

    df.drop(columns=['new_column_name', 'sorted_attributes'], inplace=True)

    for column in df.columns:
        df[column] = df[column].tolist() + [None] * (df.shape[0] - len(df[column]))

    return df

def parse_nrows(nrows):
    if nrows == '' or nrows is None:
        return None
    try:
        return int(nrows)
    except ValueError:
        logging.warning("Invalid value for load_nrows. Defaulting to load all rows.")
        return None

def load_dataframe(path, dataset_name, load_nrows=None):
    if not path:
        logging.info(f"Path for '{dataset_name}' is empty. Skipping processing.")
        return None

    try:
        df = pd.read_csv(path, nrows=load_nrows)
        logging.info(f"CSV data for '{dataset_name}' successfully loaded into DataFrame. Loaded {len(df)} rows.")
        return df
    except FileNotFoundError as e:
        logging.error(f"CSV file not found: {e}")
        return None
    except pd.errors.ParserError as e:
        logging.error(f"Error parsing CSV file: {e}")
        return None

def load_and_process_columns(config):
    logging.info("Loading and processing CSV columns.")
    processed_dataframes = {}

    for dataset_name in ['case_manager_data', 'osquery_data']:
        dataset_config = config.get(dataset_name, {})
        path = dataset_config.get('path', '')
        load_nrows = parse_nrows(dataset_config.get('load_nrows', ''))

        df = load_dataframe(path, dataset_name, load_nrows)
        if df is not None:
            processed_dataframes[dataset_name] = df
            logging.info(f"Contents of '{dataset_name}' DataFrame:\n{df}")

    combined_config = config.get('combined_case_query_data', {})
    combined_path = combined_config.get('path', '')
    combined_load_nrows = parse_nrows(combined_config.get('load_nrows', ''))
    print_combined_query_frame = combined_config.get('print_combined_case_query_data_frame', False)
    summarize_query = combined_config.get('summarize_query', False)
    generate_json_summary = combined_config.get('generate_json_summary', False)

    combined_df = load_dataframe(combined_path, 'combined_case_query_data', combined_load_nrows)
    attribute_table_map = {}

    if combined_df is not None:
        combined_df['extracted_name'] = combined_df['Query'].apply(extract_name)
        combined_df['extracted_sql_statement'] = combined_df['Query'].apply(extract_command)
        combined_df['extracted_principal_type'] = combined_df['Query'].apply(extract_principal_type)
        combined_df['extracted_query_id'] = combined_df['Query'].apply(extract_query_id)
        combined_df['extracted_query_type'] = combined_df['Query'].apply(extract_query_type)
        combined_df['extracted_query_categories'] = combined_df['Query'].apply(extract_query_categories)

        cols = combined_df.columns.tolist()
        extracted_name_index = cols.index('Query') + 1
        cols.insert(extracted_name_index, 'extracted_name')
        cols.pop(cols.index('extracted_name', extracted_name_index + 1))
        combined_df = combined_df[cols]
        summary_df = pd.DataFrame

        processed_dataframes['combined_case_query_data'] = combined_df
        logging.info(f"Contents of 'combined_case_query_data' DataFrame:\n{combined_df}")

        if print_combined_query_frame:
            combined_df.to_csv('combined_case_query_data.csv', index=False, quoting=csv.QUOTE_ALL)
            logging.info("Combined Case Query DataFrame output to 'combined_case_query_data.csv'.")

        if summarize_query:
            summary_df = summarize_case_query_data(config, combined_df, summarize_query)

        if generate_json_summary:
            export_views_to_json(combined_df, summary_df, './osquery_summary.json', True, True, True)


def summarize_case_query_data(config, combined_df, summarize_query)-> (pd.DataFrame, dict):
   
    """
    Function to generale summarized query dataframe, create the 'query_summary.csv' and return the dataframe 
    Param:
    Param:
    Param:
    Return: summarized query dataframe; dict of queries with invalid data parsed

    """

    def _check_for_sql_parse_errors(df: pd.DataFrame) -> pd.DataFrame:
        """
        Remove the 'invalid' table name from the OSQueryTable list
        Remove the 'invalid' SQL clause data included in the attribute list 
        Save the invalid keywords in a separate column.
        Presence of data in the column indicates that the query parsing function needs to be updated to support this query correctly.
        
        :param dataframe  df_summary
        :return - update dataframe; cleaned columns and new columns showing errors

        """
        sql_keywords_to_log_and_remove = ["JSON_EACH","GROUP","GROUP_CONCAT","CHAR","SELECT"]
        new_list = []
        df_new = pd.DataFrame

        # Define a function to remove multiple elements from a list and track removed elements
        def __remove_invalid_elements_and_track(lst, elements) -> (list, list):
            """
            For tables: Full match removal of "sql_keywords_to_log_and_remove"
            """
            filtered_list = [item for item in lst if item not in elements]
            removed_items = [item for item in lst if item in elements]
            return filtered_list, removed_items

        # Use the 'find' function to check if the string contains the target string
        def __remove_invalid_elements_fuzzy_match_and_track(lst, elements)-> (list, list):
            """
            For attributes: fuzzy match removal of "sql_keywords_to_log_and_remove"
            """

            # Initialize two lists to store the results
            removed_items = []
            filtered_items = []

            # Populate the lists using list comprehensions
            removed_items = [target for target in lst if any(target.find(search) != -1 for search in elements)]
            filtered_items = [target for target in lst if not any(target.find(search) != -1 for search in elements)]

            return filtered_items, removed_items


        # create a 'cleaned' tables column to keep track of the data removed from the original secops csv file
        # add a new column with the parsed data removed
        df['os_query_table_removed_items'] = df['os_query_table'].apply(
            lambda x: __remove_invalid_elements_and_track(x, sql_keywords_to_log_and_remove)[1])
        df['os_query_table'] = df['os_query_table'].apply(
            lambda x: __remove_invalid_elements_and_track(x, sql_keywords_to_log_and_remove)[0])
        # no need to include incorrect data in the 'unique' table list column
        df['unique_osquery_table'] = df['unique_osquery_table'].apply(
            lambda x: __remove_invalid_elements_and_track(x, sql_keywords_to_log_and_remove)[0])

        # create a 'cleaned' attributes column to keep track of the invalid data removed from the original secops csv file
        # add a new column with the parsed data removed
        df['query_attributes_removed_items'] = df['query_attributes'].apply(
            lambda x: __remove_invalid_elements_fuzzy_match_and_track(x, sql_keywords_to_log_and_remove)[1])        
        df['query_attributes'] = df['query_attributes'].apply(
            lambda x: __remove_invalid_elements_fuzzy_match_and_track(x, sql_keywords_to_log_and_remove)[0])  
        df['unique_osquery_attributes'] = df['unique_osquery_attributes'].apply(
            lambda x: __remove_invalid_elements_fuzzy_match_and_track(x, sql_keywords_to_log_and_remove)[0])  

        #print(df)
        #df.to_csv('temp.csv', index=False, quoting=csv.QUOTE_ALL)

        return df


    query_summary_data = []

    for _, row in combined_df.iterrows():
        if 'Query' in row and pd.notnull(row['Query']):
            try:
                query_json = json.loads(row['Query'])
            except json.JSONDecodeError:
                logging.warning("Invalid JSON format in Query column.")
                continue

            sql_query = query_json.get('command', '')
            query_name = query_json.get('name', 'Unnamed')

            # function extracts tables, attributes and new attributes from the SQL query
            tables, attributes, new_attributes = extract_sql_details(sql_query)
            #logging.info(f"\nAttributes: {attributes}")
            #logging.info(f"\nNew Attributes: {new_attributes}")
            #logging.info(f"\nTables: {tables}")

            #unique_tables and unique_attributes need to be checked for invalid SQL
            #the query_name with the invalid SQL also needs 

            unique_tables = sorted(set(tables))
            unique_attributes = sorted(set(attributes))

            

            query_summary_data.append({
                "query_name": query_name,
                "os_query_table": tables,
                "unique_osquery_table": unique_tables,
                "query_attributes": attributes,
                "unique_osquery_attributes": unique_attributes
            })

    #temp_df = pd.DataFrame(query_summary_data)
    #temp_df = _check_for_sql_parse_errors(temp_df)

    #temp_df = _check_for_sql_parse_errors(pd.DataFrame(query_summary_data))
    query_summary_df = _check_for_sql_parse_errors(pd.DataFrame(query_summary_data))

    if query_summary_df is not None:
        query_summary_df.to_csv('query_summary.csv', index=False)
        logging.info("Query Summary DataFrame output to 'query_summary.csv'.")
        return query_summary_df



def export_views_to_json(
    df_combined: pd.DataFrame, df_summarized: pd.DataFrame, json_file_path: str,
    summarize_osqueries: bool = False,
    summarize_queries_in_dataset: bool = False,
    summarize_attributes_in_dataset: bool = False,
    summarize_tables_in_dataset: bool = False
):
    """
    Export the contents of the 'views_list' column in a DataFrame to a JSON file.
    Optionally, add additional summaries to the JSON structure.
    
    :param df: The DataFrame containing the 'views_list' column.
    :param json_file_path: The path where the JSON file will be saved.
    :param summarize_osqueries: Whether to add osquery summaries to the JSON structure.
    """

    def _case_counts(column: pd.Series) -> (int, int):
        """
        Calculate the total number of unique values and the total number of values in a DataFrame column.

        :param column: A pandas Series where each entry is a string representing a list.
        :return: A tuple containing (total number of unique values, total number of values).
        """
        
        unique_values = set()
        total_value_count = 0
        
        for item in column:
            try:
                # Safely evaluate the string as a list
                value_list = ast.literal_eval(item)
                # Update the set with unique values from the list
                unique_values.update(value_list)
                # Increment the total value count by the number of items in the current list
                total_value_count += len(value_list)
            except (ValueError, SyntaxError):
                continue
        
        return len(unique_values), total_value_count
    
    def _customer_counts(column: pd.Series) -> (int, int):
        """
        Calculate the total number of unique GUIDs and the total number of GUIDs in a DataFrame column.
        
        :param column: A pandas Series where each entry is a string representing a GUID.
        :return: A tuple containing (total number of unique GUIDs, total number of GUIDs).
        """
        
        unique_values = set()
        total_value_count = 0
        
        for item in column:
            # Ensure each GUID is treated as a string and counted
            guid = str(item).strip()
            unique_values.add(guid)
            total_value_count += 1
        
        return len(unique_values), total_value_count


    def _unique_region_list(column: pd.Series) -> list:
        """
        Compute a unique region list
        
        :param column: A pandas Series where each entry is a string representing a region.
        :return: A list  containing unique list of regions
        """
        
        unique_values = set()
        
        for item in column:
            # Ensure each GUID is treated as a string and counted
            region = str(item).strip()
            unique_values.add(region)
        
        return list(unique_values)

    def _date_range(column: pd.Series) -> list:
        """
        Return date range
        :param column: A pandas Series where each element is a date to day granularity
        :return: A list containing the earliest and most recent date
        """

        unique_values = set()

        for index, item in column.items():
            # Ensure each date is first stripped before converting to date object
            try:
                date_string = str(item).strip()
                date = datetime.strptime(date_string, "%Y-%m-%d")
                unique_values.add(str(date))
            except ValueError as e:
                # Print error message with the invalid input
                print(f"Invalid date input '{date_string}': {e} in row:{index}")
        
        return list(unique_values)

    def _create_unique_table_list(df: pd.DataFrame) -> list:
        """
        param: dataframe
        return: list of unique tables
        collects all table names in the 'flattened_table_list'
        returns unique table list
        """

        unique_tables = set()

        for lst in df['flattened_table_list']:
            unique_tables.update(lst)

        return sorted(list(unique_tables))

    def _query_table_data(df: pd.DataFrame)-> pd.DataFrame:
        """
        # Group queries by tables transformed into dataframe with these columns
        # query_name: unique set of queries that tables are grouped by
        # table_list: lists of tables queried each time query occurred
        # unique_table_list: raw table list for each query 
        # Data set meta data
        # Number of unique queries (length of series returned by function)
        # Number of times each query executed (count of each query)        
        # Number of times each query was called 
        """

        #unique_values = set(df['Name'].dropna().unique())
        # Initialize a dictionary to store the results
        results = {}

        def _flatten(nested_lists):
            return [item for sublist in nested_lists for item in sublist]

        #temp_df = df[['Query Name','unique_osquery_table']]
        #print(df)
        
        # Group tables by 'Query Name'
        grouped_tables_by_query_name_series = df.groupby('query_name')['unique_osquery_table'].apply(lambda tables: list(tables))
        temp_df = grouped_tables_by_query_name_series.reset_index()
        temp_df.columns = ['query_name','table_list']

        temp_df['flattened_table_list'] = temp_df['table_list'].apply(_flatten)

        #print(df)

        grouped_removed_table_items_by_query_name_series = df.groupby('query_name')['os_query_table_removed_items']\
            .apply(lambda invalid_table_items: list(invalid_table_items))
        temp_df2 = grouped_removed_table_items_by_query_name_series.reset_index()
        temp_df2['os_query_table_removed_items'] = temp_df2['os_query_table_removed_items'].apply(_flatten)
        temp_df['os_query_table_removed_items'] = temp_df2['os_query_table_removed_items']        

        return temp_df

    # OSQuery  summary
    def add_osquery_data_stats_summary(summarize_osqueries: bool):
        print(f"add_osquery_stats_summary {summarize_osqueries}")
        if not summarize_osqueries:
            return {}

        unique_case_count, total_case_count = _case_counts(df_combined['Possible Cases'])
        unique_customer_count, total_customer_count = _customer_counts(df_combined['Customer ID'])
        stats = {"total_number_queries_analyzed": len(df_combined), 
                "number_of_unique_cases": unique_case_count, 
                "total_number_of_cases_analyzed":total_case_count,
                "number_of_unique_customers": unique_customer_count, 
                "total_number_of_customers_analyzed":total_customer_count,
                "region_list" : _unique_region_list(df_combined['Region']),
                "date_range"  : _date_range(df_combined['Created At (UTC)'])
                },
        return stats


    def add_osquery_query_analysis_summary(summarize_queries_in_dataset: bool)-> dict:
        """
        Summarize query data
            # identify by query name + unique_table
            ## frequency
            ## target attribute
            ## raw count
            ## overall percentage         
        """
        if not summarize_queries_in_dataset:
            return {}


        def __calculate_query_percentage(list_of_query_dicts: list, total_query_count: int) -> list:
            """
            Compute an insert the percentage the query was called from the entire query data set
            
            :param list_of_query_dicts: The list of query objects created
            :param total_query_count: count of total queries issued to help create percentage 
            :return: A list of the objects each with the updated percentage

            """
            updated_query_list = []

            for query_dict in list_of_query_dicts:
                number = int(query_dict["frequency_of_execution"])/total_query_count
                query_dict["query_execution_percentage"] = (round(number,5)*100)
                updated_query_list.append(query_dict)

            return updated_query_list

        def __create_queries_by_percentage(query_list: list) -> dict:
            """
            Create a 'view' of a dictionary containing a key:value pair ordered by percentage:
                      " (1)":8.0,
                      "('Informa\u00e7\u00f5es de Hardware',)":5.846
            :param - query list generated by __calculate_query_percentage
            :return - ordered dict by percent
            """
            queries_by_percentage = {}
            #pp = pprint.PrettyPrinter(indent=4)
            # Sort the dictionary by the 'value' key in descending order
            for each_query in query_list:
                #pp.pprint(each_query) 
                query_name = each_query['query_name']
                query_percentage = each_query['query_execution_percentage']
                queries_by_percentage[query_name] = query_percentage 

            sorted_query_execution_percentage = sorted(queries_by_percentage.items(), key=lambda item: item[1], reverse=True)
            # Create a new dictionary with the sorted items (maintains order if using Python 3.7+)
            sorted_dict = dict(sorted_query_execution_percentage
            )
            return sorted_dict


        def __create_queries_by_percentage_count(query_list: list) -> dict:
            """
            Create a 'view' of a dictionary containing a key:value pair ordered by percentage but includes the count:
                  {
                     "adhoc_query": {"percent":74.9,
                                      "count": 740 },
                      " (1)" {"percent":9.8,
                              "count": 98 },
                      ... 
                  }
            Call __create_queries_by_percentage and modify it according to the dict described above; return the new dict
            :param - query list generated by __calculate_query_percentage
            :return - ordered dict by percent that includes nested dict
            """
            queries_by_percentage = __create_queries_by_percentage(query_list)
            queries_by_percentage_count = queries_by_percentage
            pp = pprint.PrettyPrinter(indent=4)
            # Sort the dictionary by the 'value' key in descending 


            '''
            1. iterate through "queries_by_percentage" dict for each key
            2. Use the key to match to the "queries" list of dictionaries
            3. When the search key is found in the queries dict object, extract the 'frequency_of_execution'
            4. update the 'queries_by_percentage' dict key to have a nested dict of:
               "percentage_of_executions":<original value>"
               "number_of_executions"
                        "queries_by_percentage": {
                            "adhoc_query": 82.0,
                            "('Informa\u00e7\u00f5es de Hardware',)": 6.0,
                            " (1)": 5.0,
                            "All login events": 1.0,
                            "Browser.02.0 browser extensions": 1.0,
                            "Detection.06.0 Windows AMSI events": 1.0,
                            "File.10.0 file events": 1.0,
                            "URL activity": 1.0,
                            "Web transactions": 1.0,
                            "dir (1)": 1.0
                        },
                  {
                     "adhoc_query": {"percent":74.9,
                                      "count": 740 },
                      " (1)" {"percent":9.8,
                              "count": 98 },
                      ... 
                  }

            '''
            for key in queries_by_percentage_count.keys():
                for query in query_list:
                    #print(pp.pprint(query))
                    if "query_name" in query:
                        if query["query_name"] == key:
                            #print(f"Found... {key}")
                            nested_dict = {}
                            nested_dict["query_execution_percentage"] = query["query_execution_percentage"]
                            nested_dict["query_execution_count"] = query["frequency_of_execution"]
                            queries_by_percentage[key] = nested_dict
            return queries_by_percentage_count


        def __query_analysis_contained_some_invalid_data(column_cell: list)-> list:
            """
            Returns the data found in 'os_query_table_removed_items' if it is not none
            """
            if len[column_cell]==0:
                return []
            return 



        """
        "queries" : [
            {
                "name":"(1)",
                "frequency_of_execution": count,
                "tables_queried": <alphabateical list of tables>,
                "unique_tables_queried": <alphabetical list of tables queried>
            },
        ],
        "tables" : [
            {
            }
        
        ]

        """
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(query_table_group_summary_df) 
        # Use the pprint method to display the dictionary
        osquery_query_summary_list = []
        osquery_table_summary_list = []
        query_table_group_summary_df = _query_table_data(df_summarized)
        counter = 0
        print(f"Returned query group summary{query_table_group_summary_df}")

        for index, row in query_table_group_summary_df.iterrows():
            query_summary = {}
            query_summary['query_name'] = row['query_name']
            query_summary["frequency_of_execution"] = len(row['table_list'])
            query_summary["parsing_error_sql_content"] = ['None'] if len(row['os_query_table_removed_items']) == 0\
                  else row['os_query_table_removed_items']
            counter = counter + len(row['table_list'])
            query_summary['unique_tables_queried'] = list(set(row['flattened_table_list']))
            osquery_query_summary_list.append(query_summary)


        osquery_query_summary_list_with_percentages =  __calculate_query_percentage(osquery_query_summary_list, counter)
        query_dict={}
        query_dict["queries"] = osquery_query_summary_list_with_percentages
        query_dict["queries_by_percentage"] = __create_queries_by_percentage(query_dict["queries"])
        query_dict["queries_by_percentage_count"] = __create_queries_by_percentage_count(query_dict["queries"])

        #query_dict["tables"] = table_dict

        #print(f"Counter: {counter}")
        return query_dict


    def add_osquery_table_analysis_summary(summarize_tables_in_dataet: bool)-> dict:
        """
        Create the following table summary
            {
            "name": "Name"
            "number_of_times_queried":"total queries"
            "percentage_of_times_queried": percent
            "query_names_calling_table":[{name:, 
                                        count:}]
            "attributes_queried": "attributes_queried"
            }        
        param: yes/no boolean to provide table summary
        return: a dict with the table data        
        """


        def _generate_total_table_query_counts(df: pd.DataFrame) -> list:
            """
            param: summarized DF
            return: list of table query counts in descending order.
            """
            temp_list = []
            all_occurrences = [item for sublist in df['os_query_table'] for item in sublist]

            # Count occurrences of each unique value
            occurrence_count = Counter(all_occurrences)

            # Calculate the total number of occurrences
            total_count = sum(occurrence_count.values())

            # Calculate the percentage of each occurrence
            percentage_count = {key: round((value / total_count) * 100,2) for key, value in occurrence_count.most_common()}

            temp_list.append(dict(occurrence_count.most_common()))
            temp_list.append(percentage_count)       
            
                
            return temp_list


        def _generate_table_counts_by_query(df: pd.DataFrame) -> OrderedDict:
            """
            param: summarized DF
            return: list of table query counts summarized by query name in descending order.
            """

            # Function to compute total queries
            def __compute_total_queries(data):
                for key, queries in data.items():
                    # Calculate the total number of queries for the current key
                    total_queries = sum(query['number_of_times_queried'] for query in queries)

                    # Insert the total queries at the beginning of each list for the key
                    queries.insert(0, {'total_queries': total_queries})

                return data

            result = defaultdict(list)

            # Iterate through each row of the DataFrame
            for idx, row in df.iterrows():
                query_name = row['query_name']
                os_query_list = row['os_query_table']
                #os_query_list = row['unique_osquery_table']
                #['os_query_table']
                
                # Count occurrences of query_name for each value in the os_query_table
                for query_table in os_query_list:
                    # Check if query_name record already exists for the query_table
                    found = False
                    for entry in result[query_table]:
                        if entry['query_name'] == query_name:
                            entry['number_of_times_queried'] += 1
                            found = True
                            break
                    if not found:
                        # Add new entry if not found
                        result[query_table].append({'query_name': query_name, 'number_of_times_queried': 1})


            #pp = pprint.PrettyPrinter(indent=4)
            #pp.pprint(result)
            #print("\n")
            result = __compute_total_queries(result) 
            #pp.pprint(result)

            sorted_data = OrderedDict(
                sorted(
                    result.items(),
                    key=lambda item: item[1][0]['total_queries'],
                    reverse=True
                )
            )


            return sorted_data              




        query_table_group_summary_df = _query_table_data(df_summarized)
        table_dict={}
        nested_table_dict = {}
        nested_table_dict["name"]="fake_table_name"
        nested_table_dict["number_of_times_queried"]= 10
        nested_table_dict["attributes_queried"]="<attribute/column list>"
        nested_table_dict["queries_calling_table"]= "[query_list]"
        table_dict["unique_table_list"] = _create_unique_table_list(query_table_group_summary_df)
        table_dict["total_table_query_count"] = _generate_total_table_query_counts(df_summarized)
        table_dict["table_counts_by_queries"] = _generate_table_counts_by_query(df_summarized)



        return table_dict


    def add_osquery_attribute_analysis_summary(summarize_attributes_in_dataset: bool)-> dict:
        """
        paras: summarize_attributes_in_dataset - add the summary to the json view
        return: dictionary of data to add to the json view
        json model: <model>
        """
        if not summarize_attributes_in_dataset:
            return {}        
        attribute_model = {}

        def __create_incorrectly_parsed_attribute_list(df: pd.DataFrame, attribute_list: list) -> list:
            """
            param: dataframe
            return: list of unique attributes
            collects all attrbitues names in the dataframe 'unique_osquery_attributes'
            returns unique attributes list
            """
            unique_attributes = set()
            #invalid_attributes_list = ['SELECT',]
            #print(df)
            for lst in df['unique_osquery_attributes']:
                unique_attributes.update(lst)

            return sorted(list(unique_attributes))

        def __create_unique_attribute_list(df: pd.DataFrame) -> list:
            """
            param: dataframe
            return: list of unique attributes
            collects all attrbitues names in the dataframe 'unique_osquery_attributes'
            returns unique attributes list
            """
            unique_attributes = set()
            #print(df)
            for lst in df['unique_osquery_attributes']:
                unique_attributes.update(lst)

            return sorted(list(unique_attributes))

        def __sort_attributes_by_characters(unique_list_of_attributes: list) -> dict:
            """
            Take the unique list of attributes returned and separate into three groups.
            Group one: most valid: contains alphabetical characters
            Group two: contains both alphabetical chars and non-numeric chars: a combination of SQL clauses and real attributes
            Group three: no alphabetical chars: just garbage
            Group four: not grouped; sorting algo missed it
            param: unique list of attributes created by __create_unique_attribute_list
            return: a dictionary containing groups 1 to 3
            """
            # Initialize groups
            group_one = []
            group_two = []
            group_three = []
            group_four = []
            result = {}

            # Iterate and classify strings into groups
            for s in unique_list_of_attributes:
                if (re.match(r"^[a-zA-Z']+$", s) or
                    re.match(r"^[a-zA-Z]+$", s) or
                    re.match(r"^[a-zA-Z_]+$", s) or
                    re.match(r"^[a-zA-Z0-9]+$", s) or
                    re.match(r"^[a-zA-Z0-9_]+$", s)):
                    group_one.append(s)
                elif re.search(r"[a-zA-Z]", s) and re.search(r"\W", s):
                    group_two.append(s)
                elif not re.search(r"[a-zA-Z]", s):
                    group_three.append(s)
                else:
                    group_four.append(s)

            # Structure the results as JSON
            result["alphabetical_attributes"] = group_one
            result["alphabetical_and_non_numeric"] = group_two
            result["non_alphabetic"] = group_three
            result["not_sorted"] = group_four

            return result            

        osquery_unique_attribute_list = []
        # osquery_table_summary_list = []
        osquery_unique_attribute_list = __create_unique_attribute_list(df_summarized)
        osquery_unique_attribute_list_sorted = __sort_attributes_by_characters(osquery_unique_attribute_list)

        attribute_model["valid_attributes"] = osquery_unique_attribute_list_sorted['alphabetical_attributes']
        attribute_model["valid_attributes_and_sql"] = osquery_unique_attribute_list_sorted['alphabetical_and_non_numeric']
        attribute_model["invalid_attributes"] = osquery_unique_attribute_list_sorted['non_alphabetic']
        attribute_model["not_sorted"] = osquery_unique_attribute_list_sorted['not_sorted']

        # original
        attribute_model["unique_attribute_list"] = osquery_unique_attribute_list
        attribute_model["incorrectly_parsed_attributes"] = []

        return attribute_model



    # FDH JSON data object
    data = {
        "osquery_summary": {
            "os_query_data_analysis_stats": add_osquery_data_stats_summary(summarize_osqueries),
            "os_query_input_query_summary": add_osquery_query_analysis_summary(summarize_queries_in_dataset),
            "os_query_table_analysis_summary": add_osquery_table_analysis_summary(summarize_tables_in_dataset),
            "os_query_attribute_analysis_summary": add_osquery_attribute_analysis_summary(summarize_attributes_in_dataset)

        },
    }

    # Write the data to a JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Exported to {json_file_path}")



def main():
    """
    Dec 27th/2024:
    This script is designed differently from fdh_analyzer.py as I relied on chatgpt to provide the framework/scaffolding for the features asked.
    This script manages all program flow inside of 'load_and_process_columns' whereas fdh_analyzer does so inside of main.

    To me main is more logical place. 

    Learning to work with chatgpt requires thought and oversight when driving to a maintainable design.
    """
    yaml_path = 'osquery_data_config.yml'
    logging.info("Starting program execution.")

    #try:
    config = read_yaml_config(yaml_path)
    load_and_process_columns(config)

    #except Exception as e:
    #    logging.error("An unexpected error occurred: %s", e)

    logging.info("Program execution completed.")

if __name__ == "__main__":
    main()