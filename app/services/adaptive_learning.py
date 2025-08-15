import logging
import time
import re
import json
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class AdaptiveLearningEngine:
    """Advanced adaptive learning system for SNMP discovery optimization - File-based storage"""
    
    def __init__(self, db_session=None):
        self.db = db_session  # Keep for compatibility but don't use
        
        # Initialize data directory first
        self.data_dir = Path("data/learning")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load config after data_dir is available
        self.config = self._load_config()
        
        # File-based storage
        self.patterns_file = self.data_dir / "learned_patterns.json"
        self.strategies_file = self.data_dir / "discovery_strategies.json"
        self.capabilities_file = self.data_dir / "device_capabilities.json"
        self.history_file = self.data_dir / "discovery_history.json"
        
        # Initialize data structures
        self._load_data()
    
    def _load_config(self) -> Dict:
        """Load adaptive learning configuration"""
        config_file = self.data_dir / "learning_config.json"
        default_config = {
            'learning_enabled': True,
            'min_success_rate': 0.7,
            'max_pattern_age_days': 30,
            'strategy_optimization_threshold': 10
        }
        
        try:
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                # Create default config file
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                return default_config
        except Exception as e:
            logger.error(f"Error loading learning config: {e}")
            return default_config
    
    def _load_data(self):
        """Load all learning data from files"""
        self.patterns = self._load_json_file(self.patterns_file, {})
        self.strategies = self._load_json_file(self.strategies_file, {})
        self.capabilities = self._load_json_file(self.capabilities_file, {})
        self.history = self._load_json_file(self.history_file, [])
    
    def _load_json_file(self, file_path: Path, default_value):
        """Load JSON file with error handling"""
        try:
            if file_path.exists():
                with open(file_path, 'r') as f:
                    return json.load(f)
            else:
                # Create file with default value
                with open(file_path, 'w') as f:
                    json.dump(default_value, f, indent=2)
                return default_value
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return default_value
    
    def _save_json_file(self, file_path: Path, data):
        """Save data to JSON file with error handling"""
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving {file_path}: {e}")
    
    def learn_from_discovery(self, device_profile: Dict, data_category: str, 
                           discovered_data: Dict, strategy_used: str, 
                           discovery_time: float, oids_tried: List[str] = None) -> None:
        """Learn from a discovery attempt and update patterns"""
        if not self.config['learning_enabled']:
            return
        
        try:
            vendor = device_profile.get('vendor', 'unknown')
            model = device_profile.get('model', 'unknown')
            device_ip = device_profile.get('ip_address', 'unknown')
            
            # Extract OIDs from discovered data (sensor names contain OID info)
            successful_oids = []
            for sensor_name in discovered_data.keys():
                # Extract OID from sensor name if available
                if '_sensor_' in sensor_name:
                    # Try to extract OID from the sensor name pattern
                    parts = sensor_name.split('_sensor_')
                    if len(parts) > 1:
                        # This is a simplified approach - in practice, we'd need to store OID mappings
                        # For now, we'll use the sensor name as a key and store the OID separately
                        successful_oids.append(sensor_name)
            
            # Record discovery history
            self._record_discovery_history(
                device_ip, vendor, model, data_category, strategy_used,
                oids_tried or [], successful_oids, discovery_time,
                len(discovered_data) > 0
            )
            
            # Update strategy performance
            self._update_strategy_performance(
                vendor, model, strategy_used, data_category, discovery_time,
                len(discovered_data) > 0
            )
            
            # Learn successful patterns
            if discovered_data:
                self._learn_successful_patterns(
                    vendor, model, data_category, discovered_data, oids_tried or []
                )
            
            # Update device capabilities
            self._update_device_capabilities(device_profile, data_category, discovered_data)
            
            # Optimize strategies periodically
            self._optimize_strategies(vendor, data_category)
            
            logger.info(f"Learning engine updated with {data_category} discovery results")
            
        except Exception as e:
            logger.error(f"Error in learn_from_discovery: {e}")
    
    def get_optimized_discovery_strategy(self, device_profile: Dict, 
                                       data_category: str) -> Tuple[str, List[str]]:
        """Get the best discovery strategy and OIDs for a device"""
        vendor = device_profile.get('vendor', 'unknown')
        model = device_profile.get('model', 'unknown')
        
        # Get learned patterns for this device type
        learned_patterns = self._get_learned_patterns(vendor, model, data_category)
        
        # Get best performing strategy
        best_strategy = self._get_best_strategy(vendor, model, data_category)
        
        # Get preferred OIDs from learned patterns
        preferred_oids = self._get_preferred_oids(learned_patterns)
        
        logger.info(f"Optimized strategy for {vendor} {model} {data_category}: "
                   f"strategy={best_strategy}, oids={len(preferred_oids)}")
        
        return best_strategy, preferred_oids
    
    def predict_successful_oids(self, device_profile: Dict, data_category: str) -> List[str]:
        """Predict which OIDs are likely to succeed based on learned patterns"""
        vendor = device_profile.get('vendor', 'unknown')
        model = device_profile.get('model', 'unknown')
        
        # Get learned patterns for similar devices
        patterns = self._get_learned_patterns(vendor, model, data_category)
        
        predicted_oids = []
        for pattern in patterns:
            if pattern.get('success_rate', 0) >= self.config['min_success_rate']:
                # Get the successful OIDs from the pattern
                successful_oids = pattern.get('successful_oids', [])
                predicted_oids.extend(successful_oids)
        
        # Remove duplicates and return
        unique_oids = list(set(predicted_oids))
        logger.info(f"Predicted {len(unique_oids)} successful OIDs for {vendor} {model} {data_category}")
        return unique_oids
    
    def _record_discovery_history(self, device_ip: str, vendor: str, model: str,
                                data_category: str, strategy: str, oids_tried: List[str],
                                successful_oids: List[str], discovery_time: float, 
                                success: bool) -> None:
        """Record a discovery attempt in history"""
        try:
            history_entry = {
                'device_ip': device_ip,
                'vendor': vendor,
                'model': model,
                'data_category': data_category,
                'strategy_used': strategy,
                'oids_tried': oids_tried,
                'successful_oids': successful_oids,
                'discovery_time': discovery_time,
                'success': success,
                'discovered_at': datetime.utcnow().isoformat()
            }
            
            self.history.append(history_entry)
            
            # Keep only last 1000 entries
            if len(self.history) > 1000:
                self.history = self.history[-1000:]
            
            self._save_json_file(self.history_file, self.history)
            
        except Exception as e:
            logger.error(f"Error recording discovery history: {e}")
    
    def _update_strategy_performance(self, vendor: str, model: str, strategy: str,
                                   data_category: str, discovery_time: float, 
                                   success: bool) -> None:
        """Update strategy performance metrics"""
        try:
            strategy_key = f"{vendor}_{strategy}_{data_category}"
            
            if strategy_key not in self.strategies:
                self.strategies[strategy_key] = {
                    'vendor': vendor,
                    'model': model,
                    'strategy_name': strategy,
                    'data_category': data_category,
                    'success_count': 0,
                    'failure_count': 0,
                    'avg_discovery_time': 0.0,
                    'last_used': datetime.utcnow().isoformat(),
                    'is_preferred': False
                }
            
            strategy_data = self.strategies[strategy_key]
            
            if success:
                strategy_data['success_count'] += 1
            else:
                strategy_data['failure_count'] += 1
            
            # Update average discovery time
            total_attempts = strategy_data['success_count'] + strategy_data['failure_count']
            if total_attempts > 1:
                strategy_data['avg_discovery_time'] = (
                    (strategy_data['avg_discovery_time'] * (total_attempts - 1) + discovery_time) 
                    / total_attempts
                )
            else:
                strategy_data['avg_discovery_time'] = discovery_time
            
            strategy_data['last_used'] = datetime.utcnow().isoformat()
            
            self._save_json_file(self.strategies_file, self.strategies)
            
        except Exception as e:
            logger.error(f"Error updating strategy performance: {e}")
    
    def _learn_successful_patterns(self, vendor: str, model: str, data_category: str,
                                 discovered_data: Dict, oids_tried: List[str]) -> None:
        """Learn from successful discoveries and update patterns"""
        try:
            pattern_key = f"{vendor}_{model}_{data_category}"
            successful_oids = list(discovered_data.keys())
            
            if pattern_key not in self.patterns:
                self.patterns[pattern_key] = {
                    'vendor': vendor,
                    'model': model,
                    'data_category': data_category,
                    'successful_oids': successful_oids,
                    'success_rate': 1.0,
                    'discovery_count': 1,
                    'last_successful': datetime.utcnow().isoformat(),
                    'is_active': True
                }
            else:
                pattern = self.patterns[pattern_key]
                existing_oids = set(pattern['successful_oids'])
                new_oids = set(successful_oids)
                
                # Merge OIDs
                all_oids = list(existing_oids.union(new_oids))
                pattern['successful_oids'] = all_oids
                pattern['discovery_count'] += 1
                pattern['last_successful'] = datetime.utcnow().isoformat()
                
                # Calculate success rate from recent history
                recent_successes = sum(1 for h in self.history[-50:] 
                                     if h.get('vendor') == vendor and 
                                     h.get('model') == model and 
                                     h.get('data_category') == data_category and 
                                     h.get('success', False))
                
                recent_attempts = sum(1 for h in self.history[-50:] 
                                    if h.get('vendor') == vendor and 
                                    h.get('model') == model and 
                                    h.get('data_category') == data_category)
                
                if recent_attempts > 0:
                    pattern['success_rate'] = recent_successes / recent_attempts
            
            self._save_json_file(self.patterns_file, self.patterns)
            
        except Exception as e:
            logger.error(f"Error learning successful patterns: {e}")
    
    def _update_device_capabilities(self, device_profile: Dict, data_category: str,
                                  discovered_data: Dict) -> None:
        """Update device capabilities with discovered sensors"""
        try:
            device_ip = device_profile.get('ip_address', 'unknown')
            
            if device_ip not in self.capabilities:
                self.capabilities[device_ip] = {
                    'device_ip': device_ip,
                    'vendor': device_profile.get('vendor', 'unknown'),
                    'model': device_profile.get('model', 'unknown'),
                    'sys_object_id': device_profile.get('sys_object_id', ''),
                    'sys_descr': device_profile.get('sys_descr', ''),
                    'capabilities': {},
                    'discovered_sensors': {},
                    'last_discovery': datetime.utcnow().isoformat()
                }
            
            capabilities = self.capabilities[device_ip]
            
            if data_category not in capabilities['capabilities']:
                capabilities['capabilities'][data_category] = []
            
            # Add new sensors
            for sensor_name in discovered_data.keys():
                if sensor_name not in capabilities['capabilities'][data_category]:
                    capabilities['capabilities'][data_category].append(sensor_name)
            
            capabilities['discovered_sensors'][data_category] = discovered_data
            capabilities['last_discovery'] = datetime.utcnow().isoformat()
            
            self._save_json_file(self.capabilities_file, self.capabilities)
            
        except Exception as e:
            logger.error(f"Error updating device capabilities: {e}")
    
    def _get_learned_patterns(self, vendor: str, model: str, data_category: str) -> List[Dict]:
        """Get learned patterns for a device type"""
        try:
            patterns = []
            
            # Get patterns for exact match first
            pattern_key = f"{vendor}_{model}_{data_category}"
            if pattern_key in self.patterns:
                patterns.append(self.patterns[pattern_key])
            
            # If no exact match, get patterns for same vendor
            if not patterns:
                for key, pattern in self.patterns.items():
                    if (pattern.get('vendor') == vendor and 
                        pattern.get('data_category') == data_category and 
                        pattern.get('is_active', True)):
                        patterns.append(pattern)
            
            # Sort by success rate
            patterns.sort(key=lambda x: x.get('success_rate', 0), reverse=True)
            
            return patterns[:5]  # Return top 5 patterns
            
        except Exception as e:
            logger.error(f"Error getting learned patterns: {e}")
            return []
    
    def _get_best_strategy(self, vendor: str, model: str, data_category: str) -> str:
        """Get the best performing strategy for a device type"""
        try:
            best_strategy = 'snmp_walk'
            best_success_rate = 0.0
            
            for key, strategy in self.strategies.items():
                if (strategy.get('vendor') == vendor and 
                    strategy.get('data_category') == data_category):
                    
                    total_attempts = strategy.get('success_count', 0) + strategy.get('failure_count', 0)
                    if total_attempts >= self.config['strategy_optimization_threshold']:
                        success_rate = strategy.get('success_count', 0) / total_attempts
                        if success_rate > best_success_rate:
                            best_success_rate = success_rate
                            best_strategy = strategy.get('strategy_name', 'snmp_walk')
            
            return best_strategy
            
        except Exception as e:
            logger.error(f"Error getting best strategy: {e}")
            return 'snmp_walk'
    
    def _get_preferred_oids(self, patterns: List[Dict]) -> List[str]:
        """Get preferred OIDs from learned patterns"""
        preferred_oids = []
        
        for pattern in patterns:
            if pattern.get('success_rate', 0) >= self.config['min_success_rate']:
                preferred_oids.extend(pattern.get('successful_oids', []))
        
        # Remove duplicates and return
        return list(set(preferred_oids))
    
    def _optimize_strategies(self, vendor: str, data_category: str) -> None:
        """Periodically optimize strategies based on performance"""
        try:
            best_strategy = None
            best_success_rate = 0.0
            
            for key, strategy in self.strategies.items():
                if (strategy.get('vendor') == vendor and 
                    strategy.get('data_category') == data_category):
                    
                    total_attempts = strategy.get('success_count', 0) + strategy.get('failure_count', 0)
                    if total_attempts >= self.config['strategy_optimization_threshold']:
                        success_rate = strategy.get('success_count', 0) / total_attempts
                        if success_rate > best_success_rate:
                            best_success_rate = success_rate
                            best_strategy = key
            
            # Mark the best strategy as preferred
            if best_strategy and best_success_rate >= self.config['min_success_rate']:
                # Clear all preferred flags for this vendor/category
                for key, strategy in self.strategies.items():
                    if (strategy.get('vendor') == vendor and 
                        strategy.get('data_category') == data_category):
                        strategy['is_preferred'] = False
                
                # Set the best strategy as preferred
                self.strategies[best_strategy]['is_preferred'] = True
                self._save_json_file(self.strategies_file, self.strategies)
                
                logger.info(f"Optimized strategy for {vendor} {data_category}: "
                           f"{self.strategies[best_strategy]['strategy_name']} (success rate: {best_success_rate:.2f})")
            
        except Exception as e:
            logger.error(f"Error optimizing strategies: {e}")
    
    def get_learning_statistics(self) -> Dict:
        """Get learning system statistics"""
        try:
            stats = {
                'total_patterns': len(self.patterns),
                'total_strategies': len(self.strategies),
                'total_devices': len(self.capabilities),
                'total_discoveries': len(self.history),
                'recent_discoveries': len([h for h in self.history 
                                         if datetime.fromisoformat(h['discovered_at']) > 
                                         datetime.utcnow() - timedelta(days=7)]),
                'top_vendors': [],
                'top_strategies': []
            }
            
            # Get top vendors by discovery count
            vendor_counts = {}
            for entry in self.history:
                vendor = entry.get('vendor', 'unknown')
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
            
            stats['top_vendors'] = [
                {'vendor': vendor, 'count': count} 
                for vendor, count in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
            
            # Get top strategies by success rate
            strategy_stats = []
            for key, strategy in self.strategies.items():
                total_attempts = strategy.get('success_count', 0) + strategy.get('failure_count', 0)
                if total_attempts >= 5:
                    success_rate = strategy.get('success_count', 0) / total_attempts
                    strategy_stats.append({
                        'strategy': strategy.get('strategy_name', 'unknown'),
                        'vendor': strategy.get('vendor', 'unknown'),
                        'success_rate': success_rate
                    })
            
            stats['top_strategies'] = sorted(strategy_stats, key=lambda x: x['success_rate'], reverse=True)[:5]
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting learning statistics: {e}")
            return {} 