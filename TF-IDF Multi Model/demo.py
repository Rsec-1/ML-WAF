from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import urllib.parse
from sklearn import tree
from sklearn import metrics
import io
from sklearn.svm import LinearSVC
from sklearn.metrics import confusion_matrix
from sklearn.ensemble import RandomForestClassifier

normal_file_original = input("请输入正常样本文件路径：")
anomaly_file_original = input("请输入异常样本文件路径：")

normal_file_parse = input("请输入正常样本文件解析后保存路径：")
anomaly_file_parse = input("请输入异常样本文件解析后保存路径：")

def parse_file(file_in, file_out):
    fin = open(file_in, 'r', encoding='utf-8')
    fout = io.open(file_out, 'w', encoding='utf-8')
    lines = fin.readlines()
    res = []
    for i in range(len(lines)):
        line = lines[i].strip()
        if line.startswith("GET"):
            res.append("GET" + line.split(" ")[1])
        elif line.startswith("POST") or line.startswith("PUT"):
            url = line.split(" ")[0] + line.split(" ")[1]
            j = 1
            while True:
                if lines[i+j].startswith("Content-Length:"):
                    break
                j += 1
            j += 1
            data = lines[i+j+1].strip()
            url += '?' + data
            res.append(url)
    for line in res:
        line = urllib.parse.unquote(line).replace('\n','').lower()
        fout.write(line + '\n')
    print("文件解析完成",len(res),"requests")
    fout.close()
    fin.close()
def load_data(file):
    with open(file, 'r', encoding='utf-8') as f:
        data = f.readlines()
    result = []
    for d in data:
        d = d.strip()
        if (len(d) > 0):
            result.append(d)
    return result

parse_file(normal_file_original, normal_file_parse)
parse_file(anomaly_file_original, anomaly_file_parse)

anomaly_requests = load_data(anomaly_file_parse)
normal_requests = load_data(normal_file_parse)

all_requests = normal_requests + anomaly_requests

yAnomaly = [1] * len(anomaly_requests)
yNormal = [0] * len(normal_requests)
y = yAnomaly + yNormal

vectorizer = TfidfVectorizer(min_df=0.0, analyzer='char', sublinear_tf=True, ngram_range=(3, 3))
X = vectorizer.fit_transform(all_requests)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#train with logistic regression
lgs = LogisticRegression()
lgs.fit(X_train, y_train)
y_pred = lgs.predict(X_test)
score_test = metrics.accuracy_score(y_test, y_pred)
matrix = confusion_matrix(y_test, y_pred)

print("线性逻辑回归分数: ",score_test)
print("线性逻辑回归混淆矩阵: ")
print(matrix)

#train with decision tree
dtc =tree.DecisionTreeClassifier()
dtc.fit(X_train, y_train)
y_pred = dtc.predict(X_test)
score_test = metrics.accuracy_score(y_test, y_pred)
matrix = confusion_matrix(y_test, y_pred)

print("决策树分数: ",score_test)
print("决策树混淆矩阵: ")
print(matrix)

#train with SVM
linear_svm = LinearSVC(C=1)
linear_svm.fit(X_train, y_train)
y_pred = linear_svm.predict(X_test)
score_test = metrics.accuracy_score(y_test, y_pred)
matrix = confusion_matrix(y_test, y_pred)

print("线性SVM分数: ",score_test)
print("线性SVM混淆矩阵: ")
print(matrix)

#train with Forest
rfc = RandomForestClassifier(n_estimators=200)
rfc.fit(X_train, y_train)
y_pred = rfc.predict(X_test)
score_test = metrics.accuracy_score(y_test, y_pred)
matrix = confusion_matrix(y_test, y_pred)

print("随机森林分数: ",score_test)
print("随机森林混淆矩阵: ")
print(matrix)