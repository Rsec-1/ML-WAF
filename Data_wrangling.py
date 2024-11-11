import numpy as np
import pandas as pd
import csv
import re
import json
import os
import logging
from IPython.display import display

# 设置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def write_payloads_to_file(payloads, dest_file):
    '''写入数据到指定文件'''
    try:
        # 直接使用目标文件路径
        with open(dest_file, "w") as myfile:
            for payload in payloads:
                if payload != '':
                    myfile.write(f'{payload}\n')
        logging.info(f'Payloads successfully written to {dest_file}')
    except Exception as e:
        logging.error(f"Error writing to file {dest_file}: {e}")

def from_google_spreadsheet_to_collections(file):
    '''从CSV文件中提取SQL和XSS数据'''
    try:
        df = pd.read_csv(file)
    except FileNotFoundError:
        logging.error(f"File {file} not found")
        return
    
    sql_data = df['Payload'][df['Injection Type'] == 'SQL']
    xss_data = df['Payload'][df['Injection Type'] == 'XSS']

    logging.info(f'Number of SQL injection data points: {len(sql_data)}')
    logging.info(f'First 5 SQL injection data points: {sql_data[:5]}')

    logging.info(f'Number of XSS injection data points: {len(xss_data)}')
    logging.info(f'First 5 XSS injection data points: {xss_data[:5]}')

    write_payloads_to_file(sql_data, "SQLCollection.txt")
    write_payloads_to_file(xss_data, "XSSCollection.txt")

def from_xsuperbug_to_collections(src_file, dest_file):
    '''从XSuperBug格式的文件中提取有效负载数据'''
    try:
        with open(src_file, "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        logging.error(f"File {src_file} not found")
        return

    logging.info(f'Raw data in source file format: {lines[0]}')
    lines = [re.search(r'(.*)##(.*)##[0-9]', line).group(2) for line in lines if re.search(r'(.*)##(.*)##[0-9]', line)]
    logging.info(f'Modified data in right format: {lines[:5]}')
    
    write_payloads_to_file(lines, dest_file)

def from_cnets_to_collection(src_file, dest_file):
    '''从CNetS数据集中提取有效负载数据'''
    try:
        with open(src_file, "r") as file:
            raw_data = [json.loads(line) for line in file.readlines()]
    except FileNotFoundError:
        logging.error(f"File {src_file} not found")
        return

    data = pd.Series([obj['from'] for obj in raw_data] + [obj['to'] for obj in raw_data])
    data = data[data != '']
    data = data[[re.match(r'(.*)=(.+)', x) != None for x in data]]

    payloads = []
    for payload in data:
        temp = payload.split('&')
        payloads.extend([substring.split('=')[1] for substring in temp if len(substring.split('=')) > 1])
    
    write_payloads_to_file(payloads, dest_file)

def from_fsecurify_to_collection(src_file, dest_file):
    '''从FSecure数据集中提取有效负载数据'''
    try:
        with open(src_file, "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        logging.error(f"File {src_file} not found")
        return

    payloads = []
    for line in lines:
        splitted_address = line.split('?')
        if len(splitted_address) > 1:
            total_payload = splitted_address[1]
            temp = total_payload.split('&')
            payloads.extend([substring.split('=')[1].strip('\n') for substring in temp if len(substring.split('=')) > 1 and 'http://192.168.202' not in substring.split('=')[1] and ('select' not in substring.split('=')[1] or 'union' not in substring.split('=')[1])])
    
    payloads = list(set(payloads))  # 去重
    write_payloads_to_file(payloads, dest_file)

def from_CSIC2010_to_collection(src_file, dest_file):
    '''从CSIC2010数据集中提取HTTP有效负载数据'''
    try:
        with open(src_file, "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        logging.error(f"File {src_file} not found")
        return

    payloads = []
    payload_next_line = False
    for line in lines:
        if line.startswith('GET') and len(line.split('?')) > 1:
            total_payload = (line.split('?')[1]).split(' ')[0]
            inputs = total_payload.split('&')
            payloads.extend([input.split('=')[1] for input in inputs if len(input.split('=')) > 1])

        if line.startswith('Content-Length'):
            payload_next_line = True
        elif payload_next_line and len(line) > 2:
            inputs = line.split('&')
            payloads.extend([input.split('=')[1].strip('\n') for input in inputs if len(input.split('=')) > 1])
            payload_next_line = False
    
    payloads = list(set(payloads))  # 去重
    write_payloads_to_file(payloads, dest_file)

def main():
    '''动态输入和选择数据集'''
    # 提供选择数据集的功能
    dataset_choice = input("请选择数据集 (1: Google Spreadsheet, 2: XSuperBug, 3: CNetS, 4: FSecure, 5: CSIC2010): ")

    if dataset_choice == "1":
        file_name = input("请输入CSV文件名称 (无后缀): ")
        from_google_spreadsheet_to_collections(file_name)
    elif dataset_choice == "2":
        src_file = input("请输入XSuperBug源文件名称 (带后缀): ")
        dest_file = input("请输入目标文件名称 (带后缀): ")
        from_xsuperbug_to_collections(src_file, dest_file)
    elif dataset_choice == "3":
        src_file = input("请输入CNetS源文件名称 (无后缀): ")
        dest_file = input("请输入目标文件名称 (带后缀): ")
        from_cnets_to_collection(src_file, dest_file)
    elif dataset_choice == "4":
        src_file = input("请输入FSecure源文件名称 (带后缀): ")
        dest_file = input("请输入目标文件名称 (带后缀): ")
        from_fsecurify_to_collection(src_file, dest_file)
    elif dataset_choice == "5":
        src_file = input("请输入CSIC2010源文件名称 (带后缀): ")
        dest_file = input("请输入目标文件名称 (带后缀): ")
        from_CSIC2010_to_collection(src_file, dest_file)
    else:
        logging.error("无效的选择，请重新运行程序。")

if __name__ == "__main__":
    main()
