import torch
import torch.nn as nn
import torch.nn.functional as F
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix

from sklearn.preprocessing import StandardScaler, LabelEncoder
import numpy as np

class TrafficClassifier(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_classes=5):
        super(TrafficClassifier, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.fc3(x)  # логиты

# Преобразование признаков и предсказание
class TrafficModelWrapper:
    def __init__(self):
        self.scaler = StandardScaler()
        self.protocol_encoder = LabelEncoder()
        self.model = None
        self.fitted = False

    def preprocess(self, df: pd.DataFrame, fit=False):
        df = df.copy()
        df = df.drop(columns=["src_ip", "dst_ip", "timestamp"], errors="ignore")

        # Заполнение пропусков
        df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").fillna(0)
        df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
        df["inter_arrival"] = df["inter_arrival"].fillna(0)
        df["flags"] = df["flags"].astype(str).fillna("NONE")

        if fit:
            df["protocol"] = self.protocol_encoder.fit_transform(df["protocol"])
        else:
            df["protocol"] = self.protocol_encoder.transform(df["protocol"])

        # Конвертация в фичи
        feature_cols = ["src_port", "dst_port", "protocol", "length", "inter_arrival"]
        X = df[feature_cols].values

        if fit:
            X = self.scaler.fit_transform(X)
        else:
            X = self.scaler.transform(X)

        return torch.tensor(X, dtype=torch.float32)

    def fit_model(self, X, y, epochs=10, lr=0.001):
        input_dim = X.shape[1]
        self.model = TrafficClassifier(input_dim)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.CrossEntropyLoss()

        for epoch in range(epochs):
            self.model.train()
            optimizer.zero_grad()
            outputs = self.model(X)
            loss = criterion(outputs, y)
            loss.backward()
            optimizer.step()

        self.fitted = True

    def predict(self, X):
        self.model.eval()
        with torch.no_grad():
            logits = self.model(X)
            preds = torch.argmax(logits, dim=1)
        return preds

    def predict_and_generate_rules(self, df: pd.DataFrame):
        X = self.preprocess(df)
        preds = self.predict(X)
        actions = []
        for pred, row in zip(preds, df.iterrows()):
            ip = row[1].get("src_ip", "unknown")
            actions.append(self.map_class_to_rule(pred.item(), ip))
        return actions

    def map_class_to_rule(self, cls, ip):
        if cls == 0:
            return f"# ALLOW traffic from {ip}"
        elif cls == 1:
            return f"iptables -A INPUT -s {ip} -j DROP  # SYN Flood"
        elif cls == 2:
            return f"tc qdisc add dev eth0 root netem rate 1mbit  # Throttle UDP"
        elif cls == 3:
            return f"iptables -A INPUT -p icmp -s {ip} -j DROP  # ICMP Deprioritize"
        elif cls == 4:
            return f"iptables -A INPUT -s {ip}/24 -j DROP  # DDoS Mitigation"
        else:
            return f"# Unknown class for {ip}"
        
        
        
        
        
        
df = pd.read_csv("dir_dataset.csv")
lmap = {'normal' : 0, 'syn_flood' : 1, 'udp_flood' : 2, 'icmp_flood' : 3, 'ddos' : 4}
df['label'] = df["label"].map(lmap)

model = TrafficModelWrapper()

X = model.preprocess(df, fit=True)
y = torch.tensor(df["label"].values, dtype = torch.long)

model.fit_model(X,y, epochs=50)


df_test = pd.read_csv("normal.csv")
df_test['label'] = df_test["label"].map(lmap)


# Предобработка и инференс
X_test = model.preprocess(df_test)
y_pred = model.predict(X_test).numpy()
y_true = df_test["label"].values

# === Матрица ошибок ===
cm = confusion_matrix(y_true, y_pred, labels=[0, 4])
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["normal", "ddos"], yticklabels=["normal", "ddos"])
plt.title("Матрица ошибок")
plt.xlabel("Предсказано")
plt.ylabel("Истинно")
plt.show()

rules = model.predict_and_generate_rules(df_test)



for rule in rules[:10]:
    print(rule)