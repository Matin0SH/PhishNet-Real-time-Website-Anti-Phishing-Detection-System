
## 🚀 Features

- 📊 **Data Exploration**: Class distribution pie charts, feature correlation heatmaps, and interactive box plots using Plotly.
- 🧹 **Preprocessing**: Standardization, label encoding (-1 → 0), and stratified data splitting.
- 🔍 **Feature Selection**: Based on Random Forest importance, visualized with both static and interactive plots.
- 🤖 **Model Training**:
  - Random Forest
  - XGBoost
  - LightGBM
  - CatBoost
  - Extra Trees
  - Gradient Boosting
- 🧠 **Ensemble Learning**: A soft voting ensemble combining the top-performing models.
- 📈 **Evaluation**: Accuracy, ROC-AUC, precision-recall, and confusion matrix visualizations.
- 📦 **Modular Class Design**: All functionality encapsulated in `PhishingModelTrainer`.

## 📝 Dataset Summary

- **Shape**: 59,455 rows × 34 features
- **Target Classes**: Binary classification (`0` = legitimate, `1` = phishing)
- **Class Distribution**:
  - Legitimate (0): 32,309 samples
  - Phishing (1): 27,146 samples

## 📉 Model Performance (Accuracy)

| Model              | Accuracy |
|-------------------|----------|
| Random Forest      | 87.80%   |
| Gradient Boosting  | 86.59%   |
| XGBoost            | 85.97%   |
| Extra Trees        | 84.53%   |
| LightGBM           | 84.32%   |
| CatBoost           | 84.29%   |
| **Voting Ensemble**| *Best combination of above* |

*See `model_comparison.png` for visual accuracy and ROC comparison.*

## 📌 Setup & Usage

1. **Install dependencies**:
    ```bash
    pip install pandas numpy matplotlib seaborn scikit-learn xgboost lightgbm catboost shap plotly
    ```

2. **Run the training pipeline**:
    ```python
    from phishing_model_trainer import PhishingModelTrainer

    trainer = PhishingModelTrainer(data_path='new_approach.csv')
    trainer.load_data()
    trainer.visualize_data_distribution()
    feature_importance = trainer.feature_selection()
    results = trainer.train_models()
    ensemble_model = trainer.create_ensemble_model()
    trainer.visualize_model_comparison(results)
    ```

3. **Check outputs**:
   - Visualizations saved under `visualizations/`
   - Performance summary in `model_comparison.png`

## 📈 Visualizations

- `data_distribution.png`: Class pie chart, top 10 correlations, feature stats
- `feature_importance.png`: Top features by importance
- `model_comparison.png`: Accuracy, ROC, PR curves, and confusion matrix
- Interactive plots saved as `.html` in the `visualizations/` folder

## 💡 Future Improvements

- Incorporate advanced model tuning with Bayesian optimization.
- Deploy model via Flask or Streamlit for real-time phishing detection.
- Explore SHAP explainability and adversarial robustness.

## 👨‍💻 Author

This pipeline was developed as part of a cybersecurity machine learning project focusing on phishing detection using tabular classification models.

---

Feel free to contribute or fork this project for further research or applications in threat intelligence.
