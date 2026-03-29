import imagehash
from PIL import Image
import numpy as np
import os
import json
from datetime import datetime

class ImageHasher:
    def __init__(self):
        self.hash_database = {}
    
    def compute_hashes(self, image):
        """Compute multiple perceptual hashes for an image"""
        # Handle different image types
        if isinstance(image, np.ndarray):
            pil_image = Image.fromarray(image)
        elif hasattr(image, 'convert'):  # PIL Image or similar
            pil_image = image.convert('RGB')  # Ensure RGB mode
        elif isinstance(image, str) and os.path.exists(image):  # File path
            pil_image = Image.open(image).convert('RGB')
        else:
            raise ValueError(f"Unsupported image type: {type(image)}")
        
        return {
            'ahash': str(imagehash.average_hash(pil_image)),
            'dhash': str(imagehash.dhash(pil_image)),
            'phash': str(imagehash.phash(pil_image)),
            'timestamp': datetime.now().isoformat()
        }
    
    def calculate_similarity(self, hash1, hash2):
        """Calculate similarity between two hash sets (0-100%)"""
        similarities = {}
        
        for algo in ['ahash', 'dhash', 'phash']:
            if algo in hash1 and algo in hash2:
                try:
                    h1 = imagehash.hex_to_hash(hash1[algo])
                    h2 = imagehash.hex_to_hash(hash2[algo])
                    distance = h1 - h2
                    max_distance = 64  # Maximum possible distance for 8x8 hash
                    similarity = 100 * (1 - distance / max_distance)
                    similarities[algo] = max(0, min(similarity, 100))
                except Exception as e:
                    similarities[algo] = 0
                    print(f"❌ Error calculating {algo} similarity: {e}")
        
        # Return average similarity across all algorithms
        if similarities:
            return sum(similarities.values()) / len(similarities)
        return 0
    
    def compare_with_banks(self, image, known_banks):
        """Compare image with known bank screenshots - FIXED VERSION"""
        results = {}
        
        # Compute hashes for the target image
        try:
            target_hashes = self.compute_hashes(image)
        except Exception as e:
            print(f"❌ Error computing target hashes: {e}")
            # Return error for all banks
            for bank in known_banks:
                results[bank["short_name"]] = {
                    'similarity': 0,
                    'error': f'Target image error: {str(e)}'
                }
            return results
        
        for bank in known_banks:
            bank_short_name = bank["short_name"]
            screenshot_path = f"bank_screenshots/{bank_short_name}_main.png"
            
            if os.path.exists(screenshot_path):
                try:
                    # Load bank screenshot and compute hashes
                    bank_image = Image.open(screenshot_path).convert('RGB')
                    bank_hashes = self.compute_hashes(bank_image)
                    
                    # Calculate similarity
                    similarity = self.calculate_similarity(target_hashes, bank_hashes)
                    results[bank_short_name] = {
                        'similarity': similarity,
                        'hashes': bank_hashes
                    }
                except Exception as e:
                    print(f"❌ Error processing {bank_short_name}: {e}")
                    results[bank_short_name] = {
                        'similarity': 0,
                        'error': str(e)
                    }
            else:
                results[bank_short_name] = {
                    'similarity': 0,
                    'error': 'Screenshot not available'
                }
        
        return results
    
    def save_hashes(self, hashes, filename='data/latest_hashes.json'):
        """Save hashes to file for debugging"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(hashes, f, indent=2)
    
    def load_hashes(self, filename='data/latest_hashes.json'):
        """Load hashes from file"""
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
        return {}