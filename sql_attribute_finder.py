import re

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
                    print(f"alias group {alias_match.group(1)}")
                    attributes.append(alias_match.group(1))

            # If the segment contains a 'dot', take the part after it
            elif '.' in item:
                print("inside elif .")
                attributes.append(item.split('.')[1])

            # Otherwise, it's a direct name and keep it
            else:
                # if not (re.search('strftime', item, re.IGNORECASE) or re.search('json_extract', item, re.IGNORECASE)):
                if not re.search(r'STRFTIME|JSON_EXTRACT|datetime\(', item, re.IGNORECASE):
                    print(f"inside else appending {item}")
                    attributes.append(item)

    return attributes

# Example usage
sql_statement_1 = """
SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(time, 'unixepoch')) AS date_time,
    eventid AS event_id,
    'User authentication succeeded' AS description,
    JSON_EXTRACT(data, '$.UserData.Param1') AS username,
    JSON_EXTRACT(data, '$.UserData.Param2') AS source_machine_network,
    JSON_EXTRACT(data, '$.UserData.Param3') AS source_ip,
    '-' AS process_name,
    '-' AS logon_type,
    '-' AS user_sid,
    '-' AS target_session_id,
    '-' AS source_session_id
FROM
    sophos_windows_events
WHERE
    source = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    AND eventid = 1149
    AND JSON_EXTRACT(data, '$.UserData.Param1') LIKE '%'
    AND JSON_EXTRACT(data, '$.UserData.Param3') LIKE '%'
    AND time >= 1733710719
    AND time <= 1733761123
"""

sql_statement_2 = """
SELECT s.name, s.service_type, s.display_name, s.status, s.start_type, s.path, s.user_account,
p.name, p.cmdline, h.sha1
FROM services AS s 
LEFT JOIN processes AS p ON s.pid = p.pid 
LEFT JOIN hash AS h ON s.path = h.path
"""

sql_statement_3 = "SELECT * FROM uptime WHERE 1=0"

sql_statement_4 = """
SELECT path, data, type, strftime('%Y-%m-%d %H:%M:%S',datetime(mtime,'unixepoch')) as modified_time_local
FROM registry
WHERE key LIKE 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
OR key LIKE 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
OR key LIKE 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices'
OR key LIKE 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce'
OR key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
OR Key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
OR key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices'
OR key LIKE 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce'
"""



sql_statement_5 = """
WITH sxl_categories (id, name) AS (
    VALUES
    (0, 'Uncategorized'), 
    (1, 'Adult/Sexually Explicit'), 
    (2, 'Advertisements & Pop-Ups'), 
    (3, 'Alcohol & Tobacco'), 
    (4, 'Arts'), 
    (5, 'Blogs & Forums'),
    (6, 'Business'), 
    (7, 'Chat'), 
    (8, 'Computing & Internet'), 
    (9, 'Criminal Activity'), 
    (10, 'Downloads'), 
    (11, 'Education'), 
    (12, 'Entertainment'),
    (13, 'Fashion & Beauty'), 
    (14, 'Finance & Investment'), 
    (15, 'Food & Dining'), 
    (16, 'Gambling'), 
    (17, 'Games'), 
    (18, 'Government'), 
    (19, 'Hacking'),
    (20, 'Health & Medicine'), 
    (21, 'Hobbies & Recreation'), 
    (22, 'Hosting Sites'), 
    (23, 'Illegal Drugs'), 
    (24, 'Infrastructure'), 
    (25, 'Intimate Apparel & Swimwear'),
    (26, 'Intolerance & Hate'), 
    (27, 'Job Search & Career Development'), 
    (28, 'Kid''s Sites'), 
    (29, 'Motor Vehicles'), 
    (30, 'News'), 
    (31, 'Peer-to-Peer'),
    (32, 'Personals and Dating'), 
    (33, 'Philanthropic & Professional Orgs.'), 
    (34, 'Phishing & Fraud'), 
    (35, 'Photo Searches'), 
    (36, 'Politics'), 
    (37, 'Proxies & Translators'),
    (38, 'Real Estate'), 
    (39, 'Reference'), 
    (40, 'Religion'), 
    (41, 'Ringtones/Mobile Phone Downloads'), 
    (42, 'Search Engines'), 
    (43, 'Sex Education'),
    (44, 'Shopping'), 
    (45, 'Society & Culture'), 
    (46, 'Spam URLs'), 
    (47, 'Sports'), 
    (48, 'Spyware'), 
    (49, 'Streaming Media'), 
    (50, 'Tasteless & Offensive'),
    (51, 'Travel'), 
    (52, 'Violence'), 
    (53, 'Weapons'), 
    (54, 'Web-based E-mail'), 
    (55, 'Custom'), 
    (56, 'Anonymizing Proxies')
)

SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(swtj.time, 'unixepoch')) AS date_time,
    (SELECT username FROM users WHERE uuid = swfj.owner) AS user,
    (SELECT process_name FROM sophos_process_journal AS spj WHERE spj.sophos_pid = swfj.sophos_pid) AS process_name,
    swfj.sophos_pid,
    swtj.url,
    swtj.status_code,
    CASE
        WHEN swtj.sxl_category != '' AND swtj.threat_name != '' THEN
            swtj.decision || ' (' || COALESCE((SELECT name FROM sxl_categories WHERE id = swtj.sxl_category), swtj.sxl_category) || ' - ' || swtj.threat_name || ')'
        WHEN swtj.sxl_category != '' THEN
            swtj.decision || ' (' || COALESCE((SELECT name FROM sxl_categories WHERE id = swtj.sxl_category), swtj.sxl_category) || ')'
        WHEN swtj.threat_name != '' THEN
            swtj.decision || ' (' || swtj.threat_name || ')'
        ELSE
            swtj.decision
    END AS decision,
    CAST(
        CASE JSON_VALID(swtj.request_headers)
            WHEN 1 THEN (SELECT GROUP_CONCAT(key || ': ' || value, CHAR(10)) FROM JSON_EACH(swtj.request_headers))
            ELSE swtj.request_headers
        END AS TEXT
    ) AS request_headers,
    CAST(
        CASE JSON_VALID(swtj.response_headers)
            WHEN 1 THEN (SELECT GROUP_CONCAT(key || ': ' || value, CHAR(10)) FROM JSON_EACH(swtj.response_headers))
            ELSE swtj.response_headers
        END AS TEXT
    ) AS response_headers,
    swtj.flow_id,
    COALESCE((SELECT name FROM sxl_categories WHERE id = swtj.sxl_category), swtj.sxl_category) AS category,
    swtj.sxl_risk_level,
    swtj.threat_name,
    swtj.file_type,
    swtj.content_type,
    swtj.referrer,
    swtj.origin
FROM
    sophos_web_transaction_journal AS swtj
LEFT JOIN
    sophos_web_flow_journal AS swfj ON (
        swfj.time = (CAST(SPLIT(swtj.flow_id, '-', 0) AS INT) - 11644473600)
        AND swfj.flow_id = swtj.flow_id
    )
WHERE
    swtj.time >= 1733746873
    AND swtj.time <= 1733747363
    AND CASE
        WHEN '%' = '%' THEN 1
        ELSE CONCAT(swtj.request_headers, swtj.response_headers) LIKE '%%%'
    END
    AND CASE
        WHEN '%' = '%' THEN 1
        ELSE swtj.flow_id = '%'
    END
    AND CASE
        WHEN '%' = '%' THEN 1
        ELSE swfj.sophos_pid = '%'
    END
    AND CASE
        WHEN '%' = '%' THEN 1
        ELSE swtj.url LIKE '%'
    END;
"""




# Extract and print results
attributes1 = extract_attribute_names(sql_statement_1)
# attributes2 = extract_attribute_names(sql_statement_2)
# attributes3 = extract_attribute_names(sql_statement_3)
attributes4 = extract_attribute_names(sql_statement_4)

print('SQL Statement 1 Attributes:', attributes1)
# print('SQL Statement 2 Attributes:', attributes2)
#print('SQL Statement 3 Attributes:', attributes3)
print('SQL Statement 4 Attributes:', attributes4)