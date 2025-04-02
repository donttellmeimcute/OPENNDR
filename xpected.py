import matplotlib.pyplot as plt
from sklearn.metrics import RocCurveDisplay, auc

# Datos simulados
fpr = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
tpr = [0.0, 0.6, 0.85, 0.92, 0.96, 1.0]
roc_auc = auc(fpr, tpr)

# Crear gráfica
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'Curva ROC (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Clasificador Aleatorio')
plt.xlabel('Tasa de Falsos Positivos (FPR)')
plt.ylabel('Tasa de Verdaderos Positivos (TPR)')
plt.title('Curva ROC - Sistema de Detección de Tráfico Malicioso')
plt.legend(loc='lower right')
plt.grid(True)
plt.show()