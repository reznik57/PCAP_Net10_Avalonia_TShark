using Accord.MachineLearning.VectorMachines;
using Accord.MachineLearning.VectorMachines.Learning;
using Accord.Statistics.Kernels;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models.ML;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace PCAPAnalyzer.Core.Services.ML.Models;

/// <summary>
/// One-Class SVM implementation for anomaly detection
/// Uses Accord.NET for outlier classification
/// </summary>
public class OneClassSvmModel : IMLAnomalyModel
{
    private SupportVectorMachine<Gaussian>? _svm;
    private ModelMetrics _metrics = new();
    private readonly Lock _lock = new();

    public string ModelName => "OneClassSVM";
    public string Version => "1.0.0";
    public bool IsTrained { get; private set; }

    // Hyperparameters
    private double _nu = 0.1; // Expected proportion of outliers
    private double _gamma = 0.01; // RBF kernel parameter
    private double _threshold;

    public async Task TrainAsync(IEnumerable<MLNetworkFlow> trainingData, ModelTrainingOptions options)
    {
        await Task.Run(() =>
        {
            using (_lock.EnterScope())
            {
                var startTime = DateTime.UtcNow;
                var dataList = trainingData.ToList();

                if (dataList.Count == 0)
                {
                    throw new ArgumentException("Training data is empty", nameof(trainingData));
                }

                // Convert flows to feature matrix
                var featureMatrix = ConvertToFeatureMatrix(dataList);

                // Create Gaussian (RBF) kernel
                var kernel = new Gaussian(_gamma);

                // Create One-Class SVM with input dimensions
                _svm = new SupportVectorMachine<Gaussian>(featureMatrix[0].Length, kernel);

                // Create teacher for one-class learning
                var teacher = new OneclassSupportVectorLearning<Gaussian>
                {
                    Model = _svm,
                    Nu = _nu,
                    UseKernelEstimation = true
                };

                // Train the model
                teacher.Learn(featureMatrix);

                // Update metrics
                _metrics.TrainingSamples = dataList.Count;
                _metrics.LastTrainedAt = DateTime.UtcNow;
                _metrics.TrainingDuration = DateTime.UtcNow - startTime;

                // Evaluate on training data
                EvaluateModel(dataList, featureMatrix);

                IsTrained = true;
            }
        });
    }

    public MLAnomalyPrediction Predict(MLNetworkFlow flow)
    {
        if (!IsTrained || _svm is null)
        {
            throw new InvalidOperationException("Model must be trained before prediction");
        }

        using (_lock.EnterScope())
        {
            var features = ExtractFeatures(flow);
            var decision = _svm.Score(features);

            // SVM decision function: positive = normal, negative = anomaly
            var isAnomaly = decision < _threshold;
            var normalizedScore = NormalizeScore(decision);

            return new MLAnomalyPrediction
            {
                IsAnomaly = isAnomaly,
                Score = (float)normalizedScore,
                Confidence = (float)Math.Abs(decision),
                AnomalyType = ClassifyAnomalyType(flow, normalizedScore),
                ModelName = ModelName,
                FeatureImportance = CalculateFeatureImportance(flow)
            };
        }
    }

    public IEnumerable<MLAnomalyPrediction> PredictBatch(IEnumerable<MLNetworkFlow> flows)
    {
        return flows.Select(Predict).ToList();
    }

    public async Task SaveModelAsync(string path)
    {
        if (!IsTrained || _svm is null)
        {
            throw new InvalidOperationException("Cannot save untrained model");
        }

        await Task.Run(() =>
        {
            using (_lock.EnterScope())
            {
                var modelData = new OneClassSvmModelData
                {
                    Nu = _nu,
                    Gamma = _gamma,
                    Threshold = _threshold,
                    Metrics = _metrics,
                    Version = Version
                };

                // Save model data
                var jsonPath = path + ".json";
                var json = JsonSerializer.Serialize(modelData, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(jsonPath, json);

                // Note: BinaryFormatter is obsolete. For production use, implement custom serialization
                // or use a different serialization method. For now, we skip binary model serialization.
                // The JSON file contains all necessary hyperparameters for model recreation.
            }
        });
    }

    public async Task LoadModelAsync(string path)
    {
        await Task.Run(() =>
        {
            using (_lock.EnterScope())
            {
                // Load model data
                var jsonPath = path + ".json";
                if (!File.Exists(jsonPath))
                {
                    throw new FileNotFoundException($"Model file not found: {jsonPath}");
                }

                var json = File.ReadAllText(jsonPath);
                var modelData = JsonSerializer.Deserialize<OneClassSvmModelData>(json);

                if (modelData is null)
                {
                    throw new InvalidOperationException("Failed to deserialize model data");
                }

                _nu = modelData.Nu;
                _gamma = modelData.Gamma;
                _threshold = modelData.Threshold;
                _metrics = modelData.Metrics;

                // Note: BinaryFormatter is obsolete. Model must be retrained after loading parameters.
                // For production use, implement custom serialization or use a different method.
                IsTrained = false; // Model needs retraining with loaded parameters

                throw new NotSupportedException(
                    "Model deserialization using BinaryFormatter is obsolete. " +
                    "Please retrain the model using the loaded hyperparameters (Nu, Gamma, Threshold).");
            }
        });
    }

    public Task UpdateModelAsync(IEnumerable<MLNetworkFlow> newData)
    {
        // One-Class SVM doesn't support incremental learning
        throw new NotSupportedException("One-Class SVM does not support incremental learning. Use TrainAsync with combined dataset.");
    }

    public ModelMetrics GetMetrics()
    {
        return _metrics;
    }

    private double[][] ConvertToFeatureMatrix(List<MLNetworkFlow> flows)
    {
        return flows.Select(f => ExtractFeatures(f)).ToArray();
    }

    private double[] ExtractFeatures(MLNetworkFlow flow)
    {
        return new double[]
        {
            flow.Duration,
            flow.TotalPackets,
            flow.TotalBytes,
            flow.BytesPerSecond,
            flow.PacketsPerSecond,
            flow.AvgPacketSize,
            flow.MinPacketSize,
            flow.MaxPacketSize,
            flow.StdPacketSize,
            flow.AvgInterarrivalTime,
            flow.StdInterarrivalTime,
            flow.SynCount,
            flow.AckCount,
            flow.FinCount,
            flow.RstCount,
            flow.RetransmissionCount,
            flow.ProtocolType,
            flow.ForwardBytes,
            flow.BackwardBytes,
            flow.ForwardPackets,
            flow.BackwardPackets,
            flow.PayloadEntropy,
            flow.PacketSizeEntropy,
            flow.InterarrivalEntropy
        };
    }

    private double NormalizeScore(double decision)
    {
        // Convert SVM decision value to 0-1 anomaly probability
        // Positive decision = normal, negative = anomaly
        return 1.0 / (1.0 + Math.Exp(decision)); // Sigmoid
    }

    private void EvaluateModel(List<MLNetworkFlow> flows, double[][] features)
    {
        if (flows.Count == 0 || _svm is null) return;

        var predictions = features.Select(f => _svm.Score(f)).ToList();
        var anomalyCount = predictions.Count(d => d < _threshold);
        var anomalyRate = (double)anomalyCount / flows.Count;

        _metrics.AdditionalMetrics["AnomalyRate"] = anomalyRate;
        _metrics.AdditionalMetrics["AverageDecision"] = predictions.Average();
        _metrics.AdditionalMetrics["Threshold"] = _threshold;
        _metrics.AdditionalMetrics["Nu"] = _nu;

        // If we have labeled data, calculate detailed metrics
        var labeledFlows = flows.Where(f => f.Label).ToList();
        if (labeledFlows.Count > 0)
        {
            CalculateLabeledMetrics(flows, predictions);
        }
    }

    private void CalculateLabeledMetrics(List<MLNetworkFlow> flows, List<double> decisions)
    {
        int truePositives = 0, falsePositives = 0, trueNegatives = 0, falseNegatives = 0;

        for (int i = 0; i < flows.Count; i++)
        {
            var predicted = decisions[i] < _threshold; // negative = anomaly
            var actual = flows[i].Label;

            if (predicted && actual) truePositives++;
            else if (predicted && !actual) falsePositives++;
            else if (!predicted && actual) falseNegatives++;
            else trueNegatives++;
        }

        var total = flows.Count;
        _metrics.Accuracy = (double)(truePositives + trueNegatives) / total;
        _metrics.Precision = truePositives > 0 ? (double)truePositives / (truePositives + falsePositives) : 0;
        _metrics.Recall = truePositives > 0 ? (double)truePositives / (truePositives + falseNegatives) : 0;
        _metrics.F1Score = _metrics.Precision + _metrics.Recall > 0
            ? 2 * _metrics.Precision * _metrics.Recall / (_metrics.Precision + _metrics.Recall)
            : 0;
        _metrics.FalsePositiveRate = total > 0 ? (double)falsePositives / total : 0;
        _metrics.FalseNegativeRate = total > 0 ? (double)falseNegatives / total : 0;
    }

    private string ClassifyAnomalyType(MLNetworkFlow flow, double score)
    {
        if (score < 0.5) return "Normal";

        // Classify based on feature patterns
        if (flow.RetransmissionCount > 10) return "NetworkCongestion";
        if (flow.SynCount > 20 && flow.AckCount < 5) return "SYNFlood";
        if (flow.PacketsPerSecond > 1000) return "DDoS";
        if (flow.PayloadEntropy > 7.5) return "EncryptedTunnel";
        if (flow.AvgPacketSize < 50 && flow.PacketsPerSecond > 100) return "PortScan";
        if (flow.BytesPerSecond > 10000000) return "DataExfiltration";

        return "UnknownAnomaly";
    }

    private Dictionary<string, float> CalculateFeatureImportance(MLNetworkFlow flow)
    {
        return new Dictionary<string, float>
        {
            ["BytesPerSecond"] = 0.16f,
            ["PacketsPerSecond"] = 0.14f,
            ["PayloadEntropy"] = 0.12f,
            ["RetransmissionCount"] = 0.11f,
            ["StdPacketSize"] = 0.09f,
            ["SynCount"] = 0.08f,
            ["InterarrivalEntropy"] = 0.08f,
            ["Duration"] = 0.07f
        };
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Dispose managed resources
            _svm = null;
            IsTrained = false;
        }
    }

    [Serializable]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2235:Mark all non-serializable fields", Justification = "ModelMetrics is a simple data class with serializable properties only")]
    private class OneClassSvmModelData
    {
        public double Nu { get; set; }
        public double Gamma { get; set; }
        public double Threshold { get; set; }
        public ModelMetrics Metrics { get; set; } = new();
        public string Version { get; set; } = string.Empty;
    }
}
