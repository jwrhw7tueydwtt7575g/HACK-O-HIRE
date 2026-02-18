#!/usr/bin/env python3
"""
Behavioral Modeler Service - User profiling, peer grouping, and entity analysis
Implements KMeans clustering, cosine similarity, and Neo4j graph analytics.
"""

import logging
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from sklearn.cluster import KMeans
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("ai-intelligence")


class BehavioralModelerService:
    """Builds and maintains behavioral baselines and peer group models"""

    def __init__(self, settings, opensearch_client=None, redis_client=None, neo4j_client=None):
        self.settings = settings
        self.opensearch = opensearch_client
        self.redis = redis_client
        self.neo4j = neo4j_client
        self.scaler = StandardScaler()
        self.peer_model = None
        self.n_peer_groups = 10
        self.baseline_window_days = 30

    async def build_user_baseline(self, user_id: str) -> Dict:
        """Build behavioral baseline for a specific user from OpenSearch data"""
        # Check Redis cache first
        if self.redis:
            cached = await self.redis.get_json(f"baseline:{user_id}")
            if cached:
                return cached

        # Query OpenSearch for user's recent activity
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"user_id": user_id}},
                        {"range": {"@timestamp": {
                            "gte": f"now-{self.baseline_window_days}d",
                            "lte": "now"
                        }}}
                    ]
                }
            },
            "size": 10000,
            "sort": [{"@timestamp": "asc"}]
        }

        events = []
        if self.opensearch:
            events = await self.opensearch.scroll_search("banking-soc-logs-*", query)

        if not events:
            logger.info(f"No activity found for user {user_id}")
            return self._empty_baseline(user_id)

        baseline = self._compute_baseline(user_id, events)

        # Cache in Redis
        if self.redis:
            await self.redis.set_json(
                f"baseline:{user_id}", baseline,
                ttl=self.settings.redis.ttl_seconds if hasattr(self.settings, 'redis') else 3600
            )

        return baseline

    def _compute_baseline(self, user_id: str, events: List[Dict]) -> Dict:
        """Compute statistical baseline from event history"""
        login_hours = defaultdict(list)
        session_durations = []
        transaction_amounts = []
        daily_tx_counts = defaultdict(int)
        access_endpoints = defaultdict(int)
        geo_locations = set()

        for event in events:
            ts = event.get("@timestamp", event.get("timestamp", ""))
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00")) if isinstance(ts, str) else ts
                day_name = dt.strftime("%A")
                login_hours[day_name].append(dt.hour + dt.minute / 60.0)
                daily_tx_counts[dt.strftime("%Y-%m-%d")] += 1
            except (ValueError, AttributeError):
                pass

            if "amount" in event:
                try:
                    transaction_amounts.append(float(event["amount"]))
                except (ValueError, TypeError):
                    pass

            if "endpoint" in event:
                access_endpoints[event["endpoint"]] += 1

            geo = event.get("source_country")
            if geo and geo != "unknown":
                geo_locations.add(geo)

        # Compute statistics
        login_stats = {}
        for day, hours in login_hours.items():
            login_stats[day] = {
                "mean_hour": float(np.mean(hours)),
                "std_hour": float(np.std(hours)),
                "count": len(hours),
            }

        tx_amounts = np.array(transaction_amounts) if transaction_amounts else np.array([0])
        daily_counts = list(daily_tx_counts.values()) if daily_tx_counts else [0]

        return {
            "user_id": user_id,
            "baseline_start": (datetime.utcnow() - timedelta(days=self.baseline_window_days)).isoformat(),
            "baseline_end": datetime.utcnow().isoformat(),
            "login_times": login_stats,
            "session_durations": {
                "mean": float(np.mean(session_durations)) if session_durations else 0,
                "std": float(np.std(session_durations)) if session_durations else 0,
            },
            "transaction_volumes": {
                "mean_amount": float(np.mean(tx_amounts)),
                "std_amount": float(np.std(tx_amounts)),
                "max_amount": float(np.max(tx_amounts)),
                "mean_daily_count": float(np.mean(daily_counts)),
                "std_daily_count": float(np.std(daily_counts)),
            },
            "access_patterns": dict(sorted(access_endpoints.items(), key=lambda x: -x[1])[:20]),
            "geo_locations": list(geo_locations),
            "total_events": len(events),
            "last_updated": datetime.utcnow().isoformat(),
        }

    def _empty_baseline(self, user_id: str) -> Dict:
        return {
            "user_id": user_id,
            "baseline_start": datetime.utcnow().isoformat(),
            "baseline_end": datetime.utcnow().isoformat(),
            "login_times": {},
            "session_durations": {"mean": 0, "std": 0},
            "transaction_volumes": {"mean_amount": 0, "std_amount": 0, "max_amount": 0,
                                     "mean_daily_count": 0, "std_daily_count": 0},
            "access_patterns": {},
            "geo_locations": [],
            "total_events": 0,
            "last_updated": datetime.utcnow().isoformat(),
        }

    async def build_peer_groups(self, user_features: Dict[str, np.ndarray]) -> Dict[str, int]:
        """Cluster users into peer groups using KMeans"""
        if len(user_features) < self.n_peer_groups:
            logger.warning("Not enough users for peer grouping")
            return {uid: 0 for uid in user_features}

        user_ids = list(user_features.keys())
        X = np.array([user_features[uid] for uid in user_ids])
        X_scaled = self.scaler.fit_transform(X)

        self.peer_model = KMeans(
            n_clusters=min(self.n_peer_groups, len(user_ids)),
            random_state=42, n_init=10
        )
        labels = self.peer_model.fit_predict(X_scaled)

        assignments = {uid: int(label) for uid, label in zip(user_ids, labels)}
        logger.info(f"Built {self.n_peer_groups} peer groups from {len(user_ids)} users")
        return assignments

    async def compute_peer_deviation(self, user_id: str, user_features: np.ndarray,
                                      peer_features: np.ndarray) -> float:
        """Compute how much a user deviates from their peer group"""
        if len(peer_features) == 0:
            return 0.0
        peer_centroid = np.mean(peer_features, axis=0).reshape(1, -1)
        user_vec = user_features.reshape(1, -1)
        similarity = cosine_similarity(user_vec, peer_centroid)[0][0]
        deviation = 1.0 - similarity
        return float(max(0.0, min(1.0, deviation)))

    async def build_entity_graph(self, entity_id: str, events: List[Dict]):
        """Build entity relationship graph in Neo4j for attack chain analysis"""
        if not self.neo4j:
            return

        # Create entity node
        await self.neo4j.create_node("Entity", {
            "id": entity_id,
            "type": "user",
            "last_seen": datetime.utcnow().isoformat(),
        })

        # Create relationships from events
        systems_accessed = set()
        for event in events:
            target = event.get("computer_name") or event.get("dest_ip") or event.get("endpoint")
            if target and target not in systems_accessed:
                systems_accessed.add(target)
                await self.neo4j.create_node("System", {
                    "id": target,
                    "type": "system",
                })
                await self.neo4j.create_relationship(
                    entity_id, target, "ACCESSED",
                    {"timestamp": event.get("@timestamp", datetime.utcnow().isoformat()),
                     "event_category": event.get("event_category", "unknown")}
                )

        logger.info(f"Built graph for {entity_id}: {len(systems_accessed)} system relationships")
