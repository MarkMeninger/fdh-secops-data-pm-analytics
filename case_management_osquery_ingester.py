import ast
import csv
import json
import logging
import pprint
import re
from collections import defaultdict

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
            export_views_to_json(combined_df, summary_df, './osquery_summary.json', True, True)


def summarize_case_query_data(config, combined_df, summarize_query):
    # if not config.get('analysis', {}).get('summarize_case_query_data', False):
    #    return None

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

            tables, attributes, new_attributes = extract_sql_details(sql_query)
            logging.info(f"\nAttributes: {attributes}")
            logging.info(f"\nNew Attributes: {new_attributes}")
            logging.info(f"\nTables: {tables}")

            unique_tables = sorted(set(tables))
            unique_attributes = sorted(set(attributes))

            query_summary_data.append({
                "Query Name": query_name,
                "OS Query Table": tables,
                "unique_osquery_table": unique_tables,
                "Query Attributes": attributes,
                "unique_osquery_attributes": unique_attributes
            })

    query_summary_df = pd.DataFrame(query_summary_data)

    if query_summary_df is not None:
        query_summary_df.to_csv('query_summary.csv', index=False)
        logging.info("Query Summary DataFrame output to 'query_summary.csv'.")
        return query_summary_df



def export_views_to_json(
    df_combined: pd.DataFrame, df_summarized: pd.DataFrame, json_file_path: str,
    summarize_osqueries: bool = False,
    summarize_queries_in_dataset: bool = False
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
                "region_list" : _unique_region_list(df_combined['Region'])
                }
        return stats


    def __query_table_data(df: pd.DataFrame)-> pd.DataFrame:
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
        
        # Group by 'Query Name'
        grouped_series = df.groupby('Query Name')['unique_osquery_table'].apply(lambda tables: list(tables))
        temp_df = grouped_series.reset_index()
        temp_df.columns = ['query_name','table_list']

        temp_df['flattened_table_list'] = temp_df['table_list'].apply(_flatten)

        results["dataframe"] = temp_df
        print(temp_df)

        return temp_df



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
            new_list = []

            for query_dict in list_of_query_dicts:
                number = int(query_dict["frequency_of_execution"])/total_query_count
                query_dict["percentage_of_execution"] = (round(number,2)*100)
                new_list.append(query_dict)

            return new_list


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
        query_table_group_summary_df = __query_table_data(df_summarized)
        counter = 0
        for index, row in query_table_group_summary_df.iterrows():
            query_summary = {}
            query_summary['query_name'] = row['query_name']
            query_summary["frequency_of_execution"] = len(row['table_list'])
            counter = counter + len(row['table_list'])
            query_summary['unique_tables_queried'] = list(set(row['flattened_table_list']))
            osquery_query_summary_list.append(query_summary)


        osquery_query_summary_list_with_percentages =  __calculate_query_percentage(osquery_query_summary_list, counter)
        query_dict={}
        table_dict={}
        query_dict["queries"] = osquery_query_summary_list_with_percentages
        query_dict["tables"] = table_dict

        #print(f"Counter: {counter}")
        return query_dict

    # FDH JSON data object
    data = {
        "osquery_summary": {
            "os_query_data_analysis_stats": add_osquery_data_stats_summary(summarize_osqueries),
            "os_query_input_query_summary": add_osquery_query_analysis_summary(summarize_queries_in_dataset)
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