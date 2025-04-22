# 🧠 Модуль: TrafficModelWrapper

## Назначение

Модуль `traffic_model.py` реализует нейросетевую модель для **классификации сетевого трафика** и **автоматической генерации правил QoS и ACL** на основе предсказаний модели. Это позволяет адаптивно управлять сетевыми ресурсами, блокировать вредоносный трафик и оптимизировать пропускную способность.

---

## Основной класс: `TrafficModelWrapper`

### Методы:

#### `preprocess(df: pd.DataFrame, fit: bool = False) -> Tensor`
- Подготавливает данные для подачи в модель.
- Преобразует строковые признаки (`protocol`) в числовые.
- Масштабирует числовые признаки (`length`, `inter_arrival`, `ports` и т.д.)

#### `fit_model(X: Tensor, y: Tensor, epochs: int = 10, lr: float = 0.001)`
- Обучает нейросетевую модель на входных признаках `X` и метках `y`.
- Использует оптимизатор `Adam` и функцию потерь `CrossEntropyLoss`.

#### `predict(X: Tensor) -> Tensor`
- Выполняет инференс модели и возвращает предсказанные классы трафика.

#### `predict_and_generate_rules(df: pd.DataFrame) -> List[str]`
- Предсказывает тип трафика и генерирует соответствующее **сетевое правило** (например, ACL или QoS).
- Возвращает список строк с командами, которые можно применить на сервере/роутере.

---

## Выходные команды от нейросети

В зависимости от предсказанного класса, модель возвращает команды управления трафиком:

| Класс           | Назначение                       | Генерируемая команда (пример)                                         |
|----------------|-----------------------------------|------------------------------------------------------------------------|
| `normal`       | Разрешить трафик                  | `# ALLOW traffic from 192.168.1.10`                                   |
| `syn_flood`    | Заблокировать IP                  | `iptables -A INPUT -s 10.0.0.1 -j DROP  # SYN Flood`                   |
| `udp_flood`    | Ограничить полосу (throttle)      | `tc qdisc add dev eth0 root netem rate 1mbit  # Throttle UDP`         |
| `icmp_flood`   | Заблокировать ICMP                | `iptables -A INPUT -p icmp -s 10.0.0.2 -j DROP  # ICMP Deprioritize`   |
| `ddos`         | Заблокировать подсеть             | `iptables -A INPUT -s 10.0.0.0/24 -j DROP  # DDoS Mitigation`          |

---

## Пример использования

```python
from traffic_model import TrafficModelWrapper
import pandas as pd
import torch

# Загрузка данных
df = pd.read_csv(\"parsed/traffic.csv\")
df['label'] = df['label'].map({'normal': 0, 'syn_flood': 1, 'udp_flood': 2, 'icmp_flood': 3, 'ddos': 4})

# Инициализация и обучение
model = TrafficModelWrapper()
X = model.preprocess(df, fit=True)
y = torch.tensor(df['label'].values, dtype=torch.long)
model.fit_model(X, y, epochs=10)

# Генерация правил
rules = model.predict_and_generate_rules(df)
for rule in rules[:5]:
    print(rule)
