import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

# === 1. Загрузка и подготовка данных ===
df = pd.read_csv("parsed/edu_dataset.csv")
dt = pd.read_csv("parsed/wireshark.csv")

# Картирование меток в числа
label_map = {'normal': 0, 'syn_flood': 1, 'udp_flood': 2, 'icmp_flood': 3, 'ddos': 4}
inv_label_map = {v: k for k, v in label_map.items()}
df['label'] = df['label'].map(label_map)

# Кодирование категориальных признаков
df['protocol'] = LabelEncoder().fit_transform(df['protocol'])
df['inter_arrival'] = df['inter_arrival'].fillna(0)
df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0)
df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0)

# Выбор признаков
features = ['src_port', 'dst_port', 'protocol', 'length', 'inter_arrival']
X = df[features]
y = df['label']

# Проверка классов
present_classes = sorted(y.unique())
class_names = [inv_label_map[i] for i in present_classes]

print("✅ Найденные классы:", present_classes, "→", class_names)

# Масштабирование
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# === 2. Обучение модели XGBoost ===
model = XGBClassifier(n_estimators=100, max_depth=6, use_label_encoder=False, eval_metric='mlogloss')
model.fit(X_scaled, y)

# === 3. Предсказание и отчёт ===
dt = dt[:3000]
dt['protocol'] = LabelEncoder().fit_transform(dt['protocol'])  # ⚠️ или сохранить энкодер из train
dt['inter_arrival'] = dt['inter_arrival'].fillna(0)
dt['src_port'] = pd.to_numeric(dt['src_port'], errors='coerce').fillna(0)
dt['dst_port'] = pd.to_numeric(dt['dst_port'], errors='coerce').fillna(0)

features = ['src_port', 'dst_port', 'protocol', 'length', 'inter_arrival']
X_new = dt[features]

# Масштабирование (используем scaler, обученный на train-данных)
X_new_scaled = scaler.transform(X_new)

# === Предсказание ===

y_pred = model.predict(X_new_scaled)

print("=== Classification Report ===")
print(classification_report(y, y_pred, target_names=class_names))

# === 4. Матрица ошибок ===
cm = confusion_matrix(y, y_pred, labels=present_classes)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=class_names,
            yticklabels=class_names)
plt.title("Confusion Matrix - XGBoost")
plt.xlabel("Predicted")
plt.ylabel("True")
plt.show()

# === 5. Важность признаков ===
importances = model.feature_importances_
importance_df = pd.DataFrame({
    'Feature': features,
    'Importance': importances
}).sort_values('Importance', ascending=False)

plt.figure(figsize=(8, 5))
sns.barplot(x='Importance', y='Feature', data=importance_df, palette='viridis')
plt.title("Feature Importance - XGBoost")
plt.xlabel("Importance")
plt.ylabel("Feature")
plt.show()
