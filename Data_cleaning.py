import os
import pandas as pd
import logging
from IPython.display import display

# 配置日志
logging.basicConfig(level=logging.INFO)

def from_txt_to_dataframe(src_file, is_malicious):
    """从文件加载 payload，并创建包含标签的 DataFrame"""
    try:
        # 如果用户输入的文件路径没有扩展名，自动加上 .txt
        if not src_file.endswith('.txt'):
            src_file += '.txt'
        
        # 直接使用用户输入的文件路径，不拼接 'data' 文件夹
        with open(src_file, 'r', encoding='UTF-8') as f:
            payloads_txt = f.readlines()
    except FileNotFoundError:
        logging.error(f"File {src_file} not found")
        return pd.DataFrame()  # 返回空的 DataFrame，处理无法加载的文件
    except Exception as e:
        logging.error(f"Error reading file {src_file}: {e}")
        return pd.DataFrame()

    # 创建 DataFrame 并添加标签
    payloads = pd.DataFrame(payloads_txt, columns=['payload'])
    payloads['is_malicious'] = [is_malicious] * len(payloads)

    # 显示数据集的前5行
    logging.info(f'Loaded {len(payloads)} entries from {src_file}')
    display(payloads.head())
    
    return payloads

def clean_payloads(payloads):
    """清理数据集中的 payload"""
    # 移除空格和换行符
    payloads['payload'] = payloads['payload'].str.strip()

    # 删除空数据
    payloads = payloads[payloads['payload'].str.len() > 0]

    # 删除长度为 1 的恶意数据
    payloads = payloads[(payloads['is_malicious'] == 0) | 
                        ((payloads['is_malicious'] == 1) & (payloads['payload'].str.len() > 1))]

    # 删除重复的 payload
    payloads = payloads.drop_duplicates(subset='payload', keep='first')

    # 修复 b'<payload>' 格式
    payloads['payload'] = payloads['payload'].apply(
        lambda x: x[2:-1] if (x.startswith("b'") or x.startswith('b"')) and len(x) > 2 else x
    )
    
    return payloads

def get_user_input():
    """获取用户输入的文件名和标签"""
    files = []
    while True:
        # 获取用户输入的文件名
        filename = input("请输入要加载的文件名（不带扩展名，或输入 'done' 完成）：")
        if filename.lower() == 'done':
            break  # 输入 'done' 退出循环
        
        # 如果文件名为空，跳过当前循环
        if not filename:
            continue

        # 判断用户输入的文件是否为恶意
        is_malicious = input(f"文件 {filename} 是否为恶意数据? 输入 1 为恶意，0 为正常：")
        is_malicious = int(is_malicious) if is_malicious in ['0', '1'] else 0

        # 将文件和标签作为元组添加到文件列表
        files.append((filename, is_malicious))

    return files

def load_and_clean_data():
    """从用户输入的文件中加载并合并数据集"""
    all_payloads = []

    # 获取用户输入的文件列表
    files = get_user_input()

    # 加载并清理每个文件的数据
    for filename, is_malicious in files:
        payloads = from_txt_to_dataframe(filename, is_malicious)
        if not payloads.empty:
            all_payloads.append(payloads)

    # 如果没有任何数据
    if not all_payloads:
        logging.error("没有加载到任何有效数据")
        return pd.DataFrame()

    # 合并所有加载的数据
    payloads = pd.concat(all_payloads, ignore_index=True)

    # 清理数据集
    payloads = clean_payloads(payloads)

    # 随机打乱数据集
    payloads = payloads.sample(frac=1).reset_index(drop=True)

    return payloads

# 主程序流程
payloads = load_and_clean_data()
if not payloads.empty:
    payloads_file = input("请输入保存清理后的数据的文件名（不带扩展名）：")
    # 保存清理后的数据到 CSV 文件
    payloads.to_csv(payloads_file + '.csv', encoding='UTF-8', index=False)
    logging.info(f"清理后的数据已保存到 {payloads_file}.csv")
else:
    logging.error("没有数据可以保存.")