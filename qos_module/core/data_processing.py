from typing import Dict, Any
import pandas as pd
from sklearn.preprocessing import StandardScaler
from statsmodels.tsa.arima.model import ARIMA

class DataProcessor:
    def __init__(self, config: Dict[str, Any]):
        self.scaler = StandardScaler()
        self.config = config

    def preprocess_data(self, raw_data: pd.DataFrame) -> pd.DataFrame:
        """Обработка временных рядов"""
        data = raw_data.resample(self.config['resample_freq']).mean()
        data.fillna(method='ffill', inplace=True)
        return self.scaler.fit_transform(data)

class ARIMAPredictor:
    def __init__(self, order: tuple = (2, 1, 2)):
        self.order = order
        self.model = None

    def train(self, train_data: pd.Series):
        self.model = ARIMA(train_data, order=self.order).fit()

    def predict(self, steps: int) -> pd.Series:
        return self.model.forecast(steps=steps)