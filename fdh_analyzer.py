import pandas as pd
import yaml  # Importing yaml for configuration handling
import logging
import json
from collections import defaultdict
import csv
import pprint

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def export_views_list_to_json(
    df: pd.DataFrame, json_file_path: str,
    summarize_events: bool = False, summarize_attributes: bool = False,
    add_raw_fdh: bool = False
):
    """
    Export the contents of the 'views_list' column in a DataFrame to a JSON file.
    Optionally, add additional summaries to the JSON structure.
    
    :param df: The DataFrame containing the 'views_list' column.
    :param json_file_path: The path where the JSON file will be saved.
    :param summarize_events: Whether to add event summaries to the JSON structure.
    :param summarize_attributes: Whether to add attribute summaries to the JSON structure.
    :param add_raw_fdh: Whether to add raw FDH data to the JSON structure.
    """

    def _parse_colon_separated_string(input_string):
        """
        Parse a string separated by two colons and return a dictionary.

        :param input_string: The input string in the format 'key1:key2:value'.
        :return: A dictionary with keys 'key1', 'key2', and 'value'.
        """
        # Split the string by colons
        parts = input_string.split(':')
        if '[' in parts[2]:
            parts[2] = [item.strip() for item in parts[2].strip('[]').split(',')]
            #print(parts[2])

        #print(f"found {input_string}")
        #print(f"parts {parts[2]}")
        
        # Return a dictionary if the number of parts is as expected
        if len(parts) == 3:
            return {'key1': parts[0], 'key2': parts[1], 'key3': parts[2]}
        
        # Handle unexpected formats
        raise ValueError("The input string does not have the expected format 'key1:key2:value'.") 

    # FDH summary
    def add_fdh_summary(summarize_events):
        if not summarize_events:
            return {}

        number_of_attributes = {}
        # Calculate the number of attributes for each view in 'views_list'
        for view_name in df['views_list'].dropna().unique():
            if view_name in df.columns:
                # Count total non-None values in the column
                attribute_count = df[view_name].notna().sum()
            else:
                # Set to -1 if the column is not found in the DataFrame
                attribute_count = -1
            number_of_attributes[view_name] = int(attribute_count)

        return number_of_attributes
    
    # attribute summary

    def add_fdh_attribute_summary(summarize_attributes):
        if not summarize_attributes:
            return {}

        # Create a list to hold fdh_attributes
        fdh_attributes = []
        #

        # Iterate through 'unique' column 
        if 'unique' in df.columns:
            for cell in df['unique']:
                if cell is not None:
                    fdh_attribute = {}
                    result = _parse_colon_separated_string(cell)
                    # Create an instance of fdh_attribute dictionary using 'key2' key
                    key_name = result['key2']
                    fdh_attribute[key_name] = {"unique":True, "found_in_event_types":[result["key1"]], "no_of_unique_instances": 1, "type":result["key3"]}
                    fdh_attributes.append(fdh_attribute)

        # Iterate through 'duplicate' column
        if 'duplicate' in df.columns:
            for cell in df['duplicate']:
                if cell is not None:
                    fdh_attribute = {}
                    result = _parse_colon_separated_string(cell)
                    key_name = result['key1']
                    fdh_attribute[key_name] = {"unique":False, "found_in_event_types":result["key3"], "no_of_instances": len(result["key3"]), "type":result["key2"]}
                    fdh_attributes.append(fdh_attribute)

                    # print(f"Duplicate parsed: {result}")
        return fdh_attributes

    def add_fdh_raw_summary(add_raw_fdh):
        print("inside add_fdh_raw")
        if not add_raw_fdh:
            return {}
        
        list_of_raw_fdh_objects = []

        target_columns_df = df.drop(columns=["views_list", "unique", "duplicate"])
        print(target_columns_df)
        fdh_raw={}
        for column in target_columns_df.columns:
            fdh_raw[column] = {}
            for cell in target_columns_df[column]:
                if cell is not None:
                    temp = {}
                    output = cell.split(':')
                    fdh_raw[column][str(output[0])] = str(output[1])
        list_of_raw_fdh_objects.append(fdh_raw)
                
        return [fdh_raw]

    # views list

    if 'views_list' not in df.columns:
        raise ValueError("The DataFrame does not contain a 'views_list' column.")
    
    # Extract the 'views_list' column and drop any None values
    views_list = df['views_list'].dropna().tolist()
    # Structure the data for JSON export

    # FDH JSON data object
    data = {
        "fdh_summary": {
            "fdh_event_types": views_list,
            "number_of_attributes": add_fdh_summary(summarize_events)
        },
         "fdh_attributes": add_fdh_attribute_summary(summarize_attributes), 
         "fdh_raw_attributes" : add_fdh_raw_summary(add_raw_fdh)
    }

    # Write the data to a JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Exported to {json_file_path}")



def load_fdh_views(path):
    """Load and process the 'fdh_views' file if the path is provided, adding 'unique', 'duplicate', and a count column."""
    try:
        with open(path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        logging.error(f"File not found: {path}")
        return pd.DataFrame()
    except json.JSONDecodeError as e:
        logging.error(f"JSON decoding error in file '{path}': {e}")
        return pd.DataFrame()

    if 'views' not in data:
        logging.warning(f"No 'views' key found in {path}.")
        return pd.DataFrame()

    views = data['views']
    view_data = defaultdict(list)
    view_names = []

    for view in views:
        if 'viewName' in view and 'columns' in view:
            view_name = view['viewName']
            view_names.append(view_name)
            for column in view['columns']:
                if 'name' in column:
                    view_data[view_name].append(f"{column['name']}:{column['type']}")
                    #print(f"{column['name']}:{column['type']}")

    #print(view_data)
    max_length = max(len(names) for names in view_data.values()) + len(view_names)
    df_data = {
        name: col + [None] * (max_length - len(col)) for name, col in view_data.items()
    }
    fdh_views_df = pd.DataFrame(df_data)
    
    # Add the 'views_list' column to the DataFrame
    # Assign one 'viewName' to each row of the 'views_list' column
    views_series = pd.Series(view_names + [None] * (max_length - len(view_names)))
    fdh_views_df.insert(0, 'views_list', views_series)

    #print(fdh_views_df)
    
    # The rest of the code remains unchanged
    unique_list = []
    duplicate_list = []

    attribute_columns = defaultdict(set)
    target_columns_df = fdh_views_df.drop(columns=["views_list"])
    for col in target_columns_df.columns:
        col_attributes = set(target_columns_df[col].dropna().unique())
        unique_in_col = col_attributes - (
            set(target_columns_df.drop(columns=col).stack().dropna().unique())
        )

        for attr in col_attributes:
            attribute_columns[attr].add(col)

        for attr in unique_in_col:
            unique_list.append(f"{col}:{attr}")

    for attr, columns in attribute_columns.items():
        if len(columns) > 1:
            columns_list = list(columns)
            columns_list.sort()
            duplicate_list.append(f"{attr}:[{', '.join(columns_list)}]")

    duplicate_list.sort()
        
    max_unique_len = len(unique_list)
    max_duplicate_len = len(duplicate_list)
    adjusted_length = max(max_length, max_unique_len, max_duplicate_len)

    fdh_views_df = fdh_views_df.apply(
        lambda x: x.tolist() + [None] * (adjusted_length - len(x))
    )
    fdh_views_df['unique'] = unique_list + [None] * (adjusted_length - max_unique_len)
    fdh_views_df['duplicate'] = duplicate_list + [None] * (adjusted_length - max_duplicate_len)


    return fdh_views_df

def main():
    # Load the YAML configuration file
    config_path = 'fdh_analysis_config.yml'
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)

    fdh_config = config.get('fdh_views', {})
    fdh_path = fdh_config.get('path', '')
    print_to_csv = fdh_config.get('print_to_csv', False)
    print_fdh_frame = fdh_config.get('print_fdh_frame', False)
    summarize_to_json = fdh_config.get('summarize_to_json', False)

    # Load and process FDH views
    fdh_views_df = load_fdh_views(fdh_path)

    if not fdh_views_df.empty:
        if print_fdh_frame:
            logging.info(f"FDH Views DataFrame:\n{fdh_views_df}")

        if print_to_csv:
            fdh_views_df.to_csv('fdh_view_aggregate_data.csv', index=False)
            logging.info("FDH Views DataFrame output to 'fdh_view_aggregate_data.csv'.")

        if summarize_to_json:
            export_views_list_to_json(fdh_views_df, './fdh_summary.json', True, True, True)
            logging.info("FDH JSON Summary to 'fdh_summary.json'.")

if __name__ == "__main__":
    main()