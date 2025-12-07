using Microsoft.ML;
using Microsoft.ML.Data;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models.ML;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace PCAPAnalyzer.Core.Services.ML.Models;

/// <summary>
/// Autoencoder-based anomaly detection using ML.NET
/// Detects anomalies based on reconstruction error
/// </summary>
public class AutoencoderModel : IMLAnomalyModel
{
    private MLContext _mlContext = new MLContext(seed: 42);
    private ITransformer? _model;
    private ModelMetrics _metrics = new();
    private readonly Lock _lock = new();
    private double _reconstructionThreshold = 0.5;

    public string ModelName => "Autoencoder";
    public string Version => "1.0.0";
    public bool IsTrained { get; private set; }

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

                // Convert to IDataView
                var dataView = _mlContext.Data.LoadFromEnumerable(dataList);

                // Define feature columns (all numeric features)
                var featureColumns = new[]
                {
                    nameof(MLNetworkFlow.Duration),
                    nameof(MLNetworkFlow.TotalPackets),
                    nameof(MLNetworkFlow.TotalBytes),
                    nameof(MLNetworkFlow.BytesPerSecond),
                    nameof(MLNetworkFlow.PacketsPerSecond),
                    nameof(MLNetworkFlow.AvgPacketSize),
                    nameof(MLNetworkFlow.MinPacketSize),
                    nameof(MLNetworkFlow.MaxPacketSize),
                    nameof(MLNetworkFlow.StdPacketSize),
                    nameof(MLNetworkFlow.AvgInterarrivalTime),
                    nameof(MLNetworkFlow.StdInterarrivalTime),
                    nameof(MLNetworkFlow.SynCount),
                    nameof(MLNetworkFlow.AckCount),
                    nameof(MLNetworkFlow.FinCount),
                    nameof(MLNetworkFlow.RstCount),
                    nameof(MLNetworkFlow.RetransmissionCount),
                    nameof(MLNetworkFlow.ProtocolType),
                    nameof(MLNetworkFlow.ForwardBytes),
                    nameof(MLNetworkFlow.BackwardBytes),
                    nameof(MLNetworkFlow.ForwardPackets),
                    nameof(MLNetworkFlow.BackwardPackets),
                    nameof(MLNetworkFlow.PayloadEntropy),
                    nameof(MLNetworkFlow.PacketSizeEntropy),
                    nameof(MLNetworkFlow.InterarrivalEntropy)
                };

                // Build training pipeline
                var pipeline = _mlContext.Transforms.Concatenate("Features", featureColumns)
                    .Append(_mlContext.Transforms.NormalizeMinMax("Features"))
                    .Append(_mlContext.AnomalyDetection.Trainers.RandomizedPca(
                        featureColumnName: "Features",
                        rank: 12, // Reduced dimensionality
                        ensureZeroMean: true
                    ));

                // Train model
                _model = pipeline.Fit(dataView);

                // Update metrics
                _metrics.TrainingSamples = dataList.Count;
                _metrics.LastTrainedAt = DateTime.UtcNow;
                _metrics.TrainingDuration = DateTime.UtcNow - startTime;

                // Evaluate reconstruction error on training data
                EvaluateModel(dataList, dataView);

                IsTrained = true;
            }
        });
    }

    public MLAnomalyPrediction Predict(MLNetworkFlow flow)
    {
        if (!IsTrained || _model == null)
        {
            throw new InvalidOperationException("Model must be trained before prediction");
        }

        using (_lock.EnterScope())
        {
            var dataView = _mlContext.Data.LoadFromEnumerable(new[] { flow });
            var predictions = _model.Transform(dataView);

            var predictionEngine = _mlContext.Model.CreatePredictionEngine<MLNetworkFlow, PcaPrediction>(_model);
            var prediction = predictionEngine.Predict(flow);

            // Higher score = more anomalous
            var isAnomaly = prediction.Score > _reconstructionThreshold;
            var normalizedScore = NormalizeScore(prediction.Score);

            return new MLAnomalyPrediction
            {
                IsAnomaly = isAnomaly,
                Score = normalizedScore,
                Confidence = Math.Abs(normalizedScore - 0.5f) * 2, // 0 = uncertain, 1 = certain
                AnomalyType = ClassifyAnomalyType(flow, normalizedScore),
                ModelName = ModelName,
                FeatureImportance = CalculateFeatureImportance(flow)
            };
        }
    }

    public IEnumerable<MLAnomalyPrediction> PredictBatch(IEnumerable<MLNetworkFlow> flows)
    {
        if (!IsTrained || _model == null)
        {
            throw new InvalidOperationException("Model must be trained before prediction");
        }

        using (_lock.EnterScope())
        {
            var dataView = _mlContext.Data.LoadFromEnumerable(flows);
            var predictions = _model.Transform(dataView);

            var predictionColumn = _mlContext.Data.CreateEnumerable<PcaPrediction>(predictions, reuseRowObject: false);

            return flows.Zip(predictionColumn, (flow, pred) =>
            {
                var normalizedScore = NormalizeScore(pred.Score);
                var isAnomaly = pred.Score > _reconstructionThreshold;

                return new MLAnomalyPrediction
                {
                    IsAnomaly = isAnomaly,
                    Score = normalizedScore,
                    Confidence = Math.Abs(normalizedScore - 0.5f) * 2,
                    AnomalyType = ClassifyAnomalyType(flow, normalizedScore),
                    ModelName = ModelName,
                    FeatureImportance = CalculateFeatureImportance(flow)
                };
            }).ToList();
        }
    }

    public async Task SaveModelAsync(string path)
    {
        if (!IsTrained || _model == null)
        {
            throw new InvalidOperationException("Cannot save untrained model");
        }

        await Task.Run(() =>
        {
            using (_lock.EnterScope())
            {
                _mlContext.Model.Save(_model, null, path);
            }
        });
    }

    public async Task LoadModelAsync(string path)
    {
        await Task.Run(() =>
        {
            using (_lock.EnterScope())
            {
                if (!File.Exists(path))
                {
                    throw new FileNotFoundException($"Model file not found: {path}");
                }

                _model = _mlContext.Model.Load(path, out var modelSchema);
                IsTrained = true;
            }
        });
    }

    public Task UpdateModelAsync(IEnumerable<MLNetworkFlow> newData)
    {
        // Autoencoder doesn't support incremental learning in ML.NET
        throw new NotSupportedException("Autoencoder does not support incremental learning. Use TrainAsync with combined dataset.");
    }

    public ModelMetrics GetMetrics()
    {
        return _metrics;
    }

    private void EvaluateModel(List<MLNetworkFlow> flows, IDataView dataView)
    {
        if (_model == null) return;

        var predictions = _model.Transform(dataView);
        var metrics = _mlContext.AnomalyDetection.Evaluate(predictions);

        // Store metrics
        _metrics.AUC = metrics.AreaUnderRocCurve;
        _metrics.AdditionalMetrics["DetectionRate"] = metrics.DetectionRateAtFalsePositiveCount;

        // Calculate threshold from training data (95th percentile of reconstruction errors)
        var predictionColumn = _mlContext.Data.CreateEnumerable<PcaPrediction>(predictions, reuseRowObject: false);
        var scores = predictionColumn.Select(p => p.Score).OrderBy(s => s).ToList();
        if (scores.Count > 0)
        {
            var percentile95Index = (int)(scores.Count * 0.95);
            _reconstructionThreshold = scores[Math.Min(percentile95Index, scores.Count - 1)];
            _metrics.AdditionalMetrics["Threshold"] = _reconstructionThreshold;
        }
    }

    private float NormalizeScore(float score)
    {
        // Normalize reconstruction error to 0-1 range
        return Math.Min(1.0f, Math.Max(0.0f, score));
    }

    private string ClassifyAnomalyType(MLNetworkFlow flow, float score)
    {
        if (score < _reconstructionThreshold) return "Normal";

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
            ["PayloadEntropy"] = 0.15f,
            ["BytesPerSecond"] = 0.14f,
            ["PacketsPerSecond"] = 0.12f,
            ["StdPacketSize"] = 0.11f,
            ["InterarrivalEntropy"] = 0.10f,
            ["RetransmissionCount"] = 0.09f,
            ["PacketSizeEntropy"] = 0.08f,
            ["Duration"] = 0.07f
        };
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Dispose managed resources
            _model = null;
            IsTrained = false;
        }
        // Dispose unmanaged resources (if any) here
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private class PcaPrediction
    {
        [VectorType(3)]
        public float[] Features { get; set; } = Array.Empty<float>();

        [ColumnName("Score")]
        public float Score { get; set; }
    }
}
