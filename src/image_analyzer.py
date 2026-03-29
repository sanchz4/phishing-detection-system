import os
import io
import numpy as np
from PIL import Image
import cv2
from datetime import datetime
from tensorflow.keras.applications import VGG16
from tensorflow.keras.models import Model
from tensorflow.keras.preprocessing import image
from tensorflow.keras.applications.vgg16 import preprocess_input
from sklearn.metrics.pairwise import cosine_similarity
from skimage.metrics import structural_similarity as ssim
import tensorflow as tf

class ImageAnalyzer:
    def __init__(self):
        self.model = self._load_feature_extraction_model()
        self.bank_features = {}
    
    def _load_feature_extraction_model(self):
        """Load pre-trained VGG16 model for feature extraction"""
        print("Loading VGG16 model for feature extraction...")
        base_model = VGG16(weights='imagenet', include_top=True)
        model = Model(inputs=base_model.input, 
                     outputs=base_model.get_layer('fc2').output)
        print("VGG16 model loaded successfully!")
        return model
    
    def extract_image_features(self, img):
        """Extract features using VGG16 model"""
        # Resize image to match VGG16 input size (224x224)
        img = img.resize((224, 224))
        
        # Convert to array and preprocess for VGG16
        img_array = image.img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)
        
        # Extract features using VGG16
        features = self.model.predict(img_array, verbose=0)
        return features.flatten()
    
    def calculate_similarity(self, features1, features2):
        """Calculate cosine similarity between feature vectors"""
        features1 = features1.reshape(1, -1)
        features2 = features2.reshape(1, -1)
        
        try:
            similarity = cosine_similarity(features1, features2)[0][0]
            return similarity
        except Exception as e:
            print(f"Similarity calculation error: {e}")
            return 0
    
    def structural_similarity(self, img1, img2):
        """Calculate structural similarity index (SSIM) between two images"""
        try:
            # Convert images to grayscale
            img1_gray = cv2.cvtColor(np.array(img1), cv2.COLOR_RGB2GRAY)
            img2_gray = cv2.cvtColor(np.array(img2), cv2.COLOR_RGB2GRAY)
            
            # Resize images to same dimensions
            img2_gray = cv2.resize(img2_gray, (img1_gray.shape[1], img1_gray.shape[0]))
            
            # Calculate SSIM
            score, _ = ssim(img1_gray, img2_gray, full=True)
            return max(0, score)
        except Exception as e:
            print(f"SSIM calculation error: {e}")
            return 0
    
    def analyze_screenshot(self, test_screenshot, known_banks):
        """Analyze screenshot against known bank sites using deep learning"""
        print("Extracting deep learning features from screenshot...")
        test_features = self.extract_image_features(test_screenshot)
        
        similarities = {}
        
        for bank in known_banks:
            bank_short_name = bank["short_name"]
            
            # Try multiple screenshot types for better comparison
            screenshot_types = ["_main", "_login", "_elements"]
            best_similarity = 0
            best_type = None
            similarity_details = {}
            
            for screenshot_type in screenshot_types:
                screenshot_path = f"bank_screenshots/{bank_short_name}{screenshot_type}.png"
                
                if os.path.exists(screenshot_path):
                    try:
                        with open(screenshot_path, 'rb') as f:
                            bank_img = Image.open(io.BytesIO(f.read()))
                            
                            # Extract features using VGG16
                            bank_features = self.extract_image_features(bank_img)
                            
                            # Calculate deep learning similarity
                            feature_sim = self.calculate_similarity(test_features, bank_features)
                            
                            # Calculate structural similarity
                            structural_sim = self.structural_similarity(test_screenshot, bank_img)
                            
                            # Track the best similarity
                            overall_sim = (feature_sim + structural_sim) / 2
                            if overall_sim > best_similarity:
                                best_similarity = overall_sim
                                best_type = screenshot_type
                            
                            similarity_details[screenshot_type] = {
                                "feature_similarity": feature_sim,
                                "structural_similarity": structural_sim,
                                "overall_similarity": overall_sim
                            }
                            
                    except Exception as e:
                        print(f"Error processing {bank_short_name}{screenshot_type}: {e}")
                        similarity_details[screenshot_type] = {
                            "feature_similarity": 0,
                            "structural_similarity": 0,
                            "overall_similarity": 0,
                            "error": str(e)
                        }
                else:
                    similarity_details[screenshot_type] = {
                        "feature_similarity": 0,
                        "structural_similarity": 0,
                        "overall_similarity": 0,
                        "error": "Screenshot not available"
                    }
            
            similarities[bank_short_name] = {
                "best_similarity": best_similarity,
                "best_type": best_type,
                "all_similarities": similarity_details
            }
        
        return {"similarities": similarities, "features_extracted": True}
    
    def get_timestamp(self):
        return datetime.now().isoformat()

# Test the class
if __name__ == "__main__":
    # Test the ImageAnalyzer class
    analyzer = ImageAnalyzer()
    print("✅ ImageAnalyzer class is working correctly!")
    
    # Test with a simple image
    try:
        test_img = Image.new('RGB', (100, 100), color='red')
        features = analyzer.extract_image_features(test_img)
        print(f"✅ Feature extraction works! Feature shape: {features.shape}")
    except Exception as e:
        print(f"❌ Feature extraction error: {e}")