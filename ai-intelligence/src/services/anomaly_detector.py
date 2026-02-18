#!/usr/bin/env python3
"""
Anomaly Detector Service - Multi-model anomaly detection
Implements IsolationForest, AutoEncoder, and HBOS per architecture spec.
"""

import logging
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import uuid
import pickle

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("ai-intelligence")


class AutoEncoder:
    """Simple autoencoder for reconstruction-error-based anomaly detection"""

    def __init__(self, config: Dict):
        self.encoding_dim = config.get("encoding_dim", 32)
        self.hidden_layers = config.get("hidden_layers", [128, 64])
        self.epochs = config.get("epochs", 50)
        self.batch_size = config.get("batch_size", 256)
        self.learning_rate = config.get("learning_rate", 0.001)
        self.threshold = config.get("reconstruction_threshold", 0.05)
        self.model = None
        self.scaler = StandardScaler()
        self._trained = False

    def fit(self, X: np.ndarray):
        """Train autoencoder on normal data"""
        try:
            from sklearn.neural_network import MLPRegressor
            X_scaled = self.scaler.fit_transform(X)
            self.model = MLPRegressor(
                hidden_layer_sizes=tuple(self.hidden_layers + [self.encoding_dim] + self.hidden_layers[::-1]),
                max_iter=self.epochs,
                learning_rate_init=self.learning_rate,
                batch_size=min(self.batch_size, len(X)),
                random_state=42,
            )
            self.model.fit(X_scaled, X_scaled)
            self._trained = True
            logger.info(f"AutoEncoder trained on {len(X)} samples")
        except Exception as e:
            logger.error(f"AutoEncoder training failed: {e}")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Return reconstruction errors and anomaly labels"""
        if not self._trained:
            return np.zeros(len(X)), np.zeros(len(X))
        X_scaled = self.scaler.transform(X)
        X_reconstructed = self.model.predict(X_scaled)
        errors = np.mean(np.square(X_scaled - X_reconstructed), axis=1)
        labels = (errors > self.threshold).astype(int)
        return errors, labels


class HBOS:
    """Histogram-Based Outlier Score — lightweight, fast outlier detection"""

    def __init__(self, config: Dict):
        self.n_bins = config.get("n_bins", 50)
        self.alpha = config.get("alpha", 0.1)
        self.contamination = config.get("contamination", 0.1)
        self.histograms = []
        self.bin_edges = []
        self._trained = False

    def fit(self, X: np.ndarray):
        """Build histograms for each feature"""
        self.histograms = []
        self.bin_edges = []
        for col in range(X.shape[1]):
            hist, edges = np.histogram(X[:, col], bins=self.n_bins, density=True)
            hist = np.maximum(hist, self.alpha)
            self.histograms.append(hist)
            self.bin_edges.append(edges)
        self._trained = True
        logger.info(f"HBOS trained on {len(X)} samples, {X.shape[1]} features")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Compute HBOS scores"""
        if not self._trained:
            return np.zeros(len(X)), np.zeros(len(X))
        scores = np.zeros(len(X))
        for col in range(X.shape[1]):
            bin_indices = np.digitize(X[:, col], self.bin_edges[col]) - 1
            bin_indices = np.clip(bin_indices, 0, len(self.histograms[col]) - 1)
            scores += -np.log(self.histograms[col][bin_indices])
        threshold = np.percentile(scores, 100 * (1 - self.contamination))
        labels = (scores > threshold).astype(int)
        return scores, labels


class AnomalyDetectorService:
    """Multi-model anomaly detection service"""

    def __init__(self, settings, redis_client=None):
        self.settings = settings
        self.redis = redis_client
        ml_config = settings.ml if hasattr(settings, 'ml') else settings

        # IsolationForest
        if_config = ml_config.isolation_forest if hasattr(ml_config, 'isolation_forest') else ml_config.get("isolation_forest", {})
        if isinstance(if_config, dict):
            self.isolation_forest = IsolationForest(
                contamination=if_config.get("contamination", 0.1),
                n_estimators=if_config.get("n_estimators", 100),
                max_samples=if_config.get("max_samples", "auto"),
                random_state=if_config.get("random_state", 42),
            )
        else:
            self.isolation_forest = IsolationForest(
                contamination=if_config.contamination,
                n_estimators=if_config.n_estimators,
                random_state=42,
            )

        # AutoEncoder
        ae_config = ml_config.autoencoder if hasattr(ml_config, 'autoencoder') else ml_config.get("autoencoder", {})
        self.autoencoder = AutoEncoder(ae_config if isinstance(ae_config, dict) else ae_config.dict())

        # HBOS
        hbos_config = ml_config.hbos if hasattr(ml_config, 'hbos') else ml_config.get("hbos", {})
        self.hbos = HBOS(hbos_config if isinstance(hbos_config, dict) else hbos_config.dict())

        self.scaler = StandardScaler()
        self._if_trained = False

    async def train_all_models(self, feature_matrix: np.ndarray):
        """Train all anomaly detection models on normal data"""
        if len(feature_matrix) < 10:
            logger.warning("Insufficient data for model training")
            return
        X_scaled = self.scaler.fit_transform(feature_matrix)
        self.isolation_forest.fit(X_scaled)
        self._if_trained = True
        self.autoencoder.fit(feature_matrix)
        self.hbos.fit(feature_matrix)
        logger.info(f"All models trained on {len(feature_matrix)} samples")

        if self.redis:
            await self.redis.set_json("anomaly_models_metadata", {
                "trained_at": datetime.utcnow().isoformat(),
                "sample_count": len(feature_matrix),
                "feature_count": feature_matrix.shape[1],
            })

    async def detect_anomalies(self, features: np.ndarray, entity_id: str) -> List[Dict]:
        """Run all models and return ensemble anomaly results"""
        results = []
        if len(features.shape) == 1:
            features = features.reshape(1, -1)

        # IsolationForest
        if self._if_trained:
            X_scaled = self.scaler.transform(features)
            if_scores = self.isolation_forest.decision_function(X_scaled)
            if_labels = self.isolation_forest.predict(X_scaled)
            for i, (score, label) in enumerate(zip(if_scores, if_labels)):
                if label == -1:
                    results.append({
                        "anomaly_id": str(uuid.uuid4()),
                        "entity_id": entity_id,
                        "detection_method": "isolation_forest",
                        "anomaly_score": float(min(1.0, max(0.0, -score))),
                        "confidence": 0.85,
                        "timestamp": datetime.utcnow().isoformat(),
                    })

        # AutoEncoder
        ae_errors, ae_labels = self.autoencoder.predict(features)
        for i, (error, label) in enumerate(zip(ae_errors, ae_labels)):
            if label == 1:
                results.append({
                    "anomaly_id": str(uuid.uuid4()),
                    "entity_id": entity_id,
                    "detection_method": "autoencoder",
                    "anomaly_score": float(min(1.0, error)),
                    "confidence": 0.80,
                    "timestamp": datetime.utcnow().isoformat(),
                })

        # HBOS
        hbos_scores, hbos_labels = self.hbos.predict(features)
        for i, (score, label) in enumerate(zip(hbos_scores, hbos_labels)):
            if label == 1:
                results.append({
                    "anomaly_id": str(uuid.uuid4()),
                    "entity_id": entity_id,
                    "detection_method": "hbos",
                    "anomaly_score": float(min(1.0, score / (np.max(hbos_scores) + 1e-10))),
                    "confidence": 0.70,
                    "timestamp": datetime.utcnow().isoformat(),
                })

        return results
