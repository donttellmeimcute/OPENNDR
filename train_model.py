import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
from ipaddress import ip_address

class NetworkTrainer:
    def __init__(self):
        self.data_file = "network_data.csv"
        self.model_file = "network_model.pkl"
        self.expected_features = [
            'hour', 'sport', 'dport', 'length', 'local_ip',
            'proto_2', 'proto_6', 'proto_17', 'payload_ratio'
        ]

    def _is_local_ip(self, ip):
        try:
            return ip_address(ip).is_private
        except:
            return False

    def preprocess(self, df):
        # Conversión de timestamp
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        
        # Direcciones locales
        df['local_ip'] = df['src_ip'].apply(self._is_local_ip).astype(int)
        
        # Protocolos específicos
        for proto in [2, 6, 17]:
            df[f'proto_{proto}'] = (df['proto'] == proto).astype(int)
        
        # Ratio de payload
        df['payload_ratio'] = 0.0
        if 'payload_len' in df.columns:
            df['payload_ratio'] = df['payload_len'] / df['length'].replace(0, 1)
        
        return df[self.expected_features]

    def train(self):
        # Cargar y limpiar datos
        df = pd.read_csv(self.data_file)
        df = df.dropna(subset=['proto', 'src_ip', 'dst_ip'])
        df = df.drop_duplicates()

        # Preprocesamiento
        processed = self.preprocess(df)
        
        # Entrenar modelo
        model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            max_features=0.85,
            random_state=42,
            verbose=1
        )
        
        model.fit(processed)
        
        # Guardar modelo con metadatos
        joblib.dump({
            'model': model,
            'features': self.expected_features,
            'protocols': [2, 6, 17],
            'metadata': {
                'training_samples': len(df),
                'last_trained': pd.Timestamp.now().strftime("%Y-%m-%d %H:%M"),
            }
        }, self.model_file)
        
        print(f"Modelo entrenado con {len(df)} muestras. Características:")
        print(self.expected_features)

if __name__ == "__main__":
    trainer = NetworkTrainer()
    trainer.train()