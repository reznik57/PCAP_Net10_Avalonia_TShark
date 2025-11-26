using PCAPAnalyzer.Core.Models.ML;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Interface for ML-based anomaly detection models
/// </summary>
public interface IMLAnomalyModel : IDisposable
{
    /// <summary>
    /// Name of the model
    /// </summary>
    string ModelName { get; }

    /// <summary>
    /// Model version
    /// </summary>
    string Version { get; }

    /// <summary>
    /// Whether the model has been trained
    /// </summary>
    bool IsTrained { get; }

    /// <summary>
    /// Train the model on labeled data
    /// </summary>
    Task TrainAsync(IEnumerable<MLNetworkFlow> trainingData, ModelTrainingOptions options);

    /// <summary>
    /// Predict anomaly for a single flow
    /// </summary>
    MLAnomalyPrediction Predict(MLNetworkFlow flow);

    /// <summary>
    /// Predict anomalies for multiple flows
    /// </summary>
    IEnumerable<MLAnomalyPrediction> PredictBatch(IEnumerable<MLNetworkFlow> flows);

    /// <summary>
    /// Save trained model to disk
    /// </summary>
    Task SaveModelAsync(string path);

    /// <summary>
    /// Load trained model from disk
    /// </summary>
    Task LoadModelAsync(string path);

    /// <summary>
    /// Update model with new data (incremental learning)
    /// </summary>
    Task UpdateModelAsync(IEnumerable<MLNetworkFlow> newData);

    /// <summary>
    /// Get model performance metrics
    /// </summary>
    ModelMetrics GetMetrics();
}

/// <summary>
/// Options for model training
/// </summary>
public class ModelTrainingOptions
{
    public int MaxIterations { get; set; } = 100;
    public float LearningRate { get; set; } = 0.01f;
    public int BatchSize { get; set; } = 32;
    public float ValidationSplit { get; set; } = 0.2f;
    public bool EnableEarlyStopping { get; set; } = true;
    public int EarlyStoppingPatience { get; set; } = 10;
    public string MetricToOptimize { get; set; } = "F1Score";
    public bool EnableCrossValidation { get; set; }
    public int NumberOfFolds { get; set; } = 5;
}

/// <summary>
/// Model performance metrics
/// </summary>
public class ModelMetrics
{
    public double Accuracy { get; set; }
    public double Precision { get; set; }
    public double Recall { get; set; }
    public double F1Score { get; set; }
    public double AUC { get; set; }
    public double FalsePositiveRate { get; set; }
    public double FalseNegativeRate { get; set; }
    public DateTime LastTrainedAt { get; set; }
    public int TrainingSamples { get; set; }
    public TimeSpan TrainingDuration { get; set; }
    public Dictionary<string, double> AdditionalMetrics { get; set; } = new();
}
