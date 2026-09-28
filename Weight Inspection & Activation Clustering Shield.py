import logging
import numpy as np
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname).4s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("WeightInspection_Shield")


@dataclass
class InspectionResult:
    status: str
    anomaly_detected: bool
    confidence_score: float
    audit_notes: List[str]


class WeightSpaceInspectionShield:
    def __init__(self, activation_threshold: float = 3.5):
        self.threshold = activation_threshold
        logger.info("Initialized Weight-Space Inspection & Activation Clustering Shield.")

    def _cluster_activations(self, layer_activations: np.ndarray) -> float:
        mean_vector = np.mean(layer_activations, axis=0)
        distances = np.linalg.norm(layer_activations - mean_vector, axis=1)
        max_deviation = float(np.max(distances))
        return max_deviation

    def inspect_model_weights(self, model_weights: Dict[str, np.ndarray], probe_activations: Dict[str, np.ndarray]) -> InspectionResult:
        logger.info("Beginning spectral weight analysis and activation clustering audit...")
        audit_logs = []
        max_anomaly_score = 0.0

        for layer_name, weights in model_weights.items():
            weight_std = np.std(weights)
            if weight_std > 2.5:
                audit_logs.append(f"High variance detected in weight matrix: {layer_name} (Std: {weight_std:.2f})")
                max_anomaly_score = max(max_anomaly_score, weight_std)

        for layer_name, activations in probe_activations.items():
            deviation = self._cluster_activations(activations)
            if deviation > self.threshold:
                audit_logs.append(f"Activation clustering anomaly found in: {layer_name} (Deviation: {deviation:.2f})")
                max_anomaly_score = max(max_anomaly_score, deviation)

        is_compromised = max_anomaly_score > self.threshold
        status = "quarantined" if is_compromised else "verified_secure"

        if is_compromised:
            logger.warning(f"Trojan Backdoor Alert! Model quarantined due to weight anomaly score: {max_anomaly_score:.2f}")
        else:
            logger.info("Weight inspection passed successfully. No backdoor triggers found.")

        return InspectionResult(
            status=status,
            anomaly_detected=is_compromised,
            confidence_score=round(max_anomaly_score, 2),
            audit_notes=audit_logs
        )


if __name__ == "__main__":
    shield = WeightSpaceInspectionShield()

    mock_weights = {
        "transformer.layer_0.attention": np.random.normal(0, 1, (512, 512)),
        "transformer.layer_1.mlp": np.random.normal(0, 3.2, (512, 512))
    }
    
    mock_activations = {
        "layer_1_probe": np.random.normal(0, 1.1, (100, 64))
    }

    result = shield.inspect_model_weights(mock_weights, mock_activations)

    print(f"\nInspection Status : {result.status.upper()}")
    print(f"Anomaly Detected  : {result.anomaly_detected}")
    print(f"Confidence Score  : {result.confidence_score}")
    print(f"Audit Notes       : {result.audit_notes}")