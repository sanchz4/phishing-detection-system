from bs4 import BeautifulSoup
import difflib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import re

class HTMLComparator:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    
    def extract_html_features(self, html_content):
        """Extract structural and content features from HTML"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        features = {
            'forms': [],
            'inputs': [],
            'buttons': [],
            'text_content': '',
            'links': [],
            'scripts': [],
            'meta_tags': []
        }
        
        # Extract forms and inputs
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', ''),
                'inputs': []
            }
            for input_tag in form.find_all('input'):
                form_info['inputs'].append({
                    'type': input_tag.get('type', ''),
                    'name': input_tag.get('name', ''),
                    'id': input_tag.get('id', '')
                })
            features['forms'].append(form_info)
        
        # Extract text content
        features['text_content'] = soup.get_text()
        
        # Extract links
        features['links'] = [a.get('href') for a in soup.find_all('a') if a.get('href')]
        
        # Extract scripts
        features['scripts'] = [script.get('src') for script in soup.find_all('script') if script.get('src')]
        
        return features
    
    def compare_html_structures(self, features1, features2):
        """Compare HTML structures using multiple metrics"""
        similarities = {}
        
        # Form structure similarity
        form_sim = self._compare_forms(features1['forms'], features2['forms'])
        similarities['form_similarity'] = form_sim
        
        # Text content similarity
        text_sim = self._compare_text_content(features1['text_content'], features2['text_content'])
        similarities['content_similarity'] = text_sim
        
        # Link structure similarity
        link_sim = self._compare_links(features1['links'], features2['links'])
        similarities['link_similarity'] = link_sim
        
        return similarities
    
    def _compare_forms(self, forms1, forms2):
        """Compare form structures"""
        if not forms1 or not forms2:
            return 0.0
        
        # Compare number of forms
        form_count_sim = 1 - abs(len(forms1) - len(forms2)) / max(len(forms1), len(forms2))
        
        # Compare form structures
        form_struct_sim = 0.0
        for form1 in forms1:
            for form2 in forms2:
                # Compare input types and names
                input_types1 = {inp['type'] for inp in form1['inputs']}
                input_types2 = {inp['type'] for inp in form2['inputs']}
                type_sim = len(input_types1.intersection(input_types2)) / max(len(input_types1), len(input_types2))
                
                form_struct_sim = max(form_struct_sim, type_sim)
        
        return (form_count_sim + form_struct_sim) / 2
    
    def _compare_text_content(self, text1, text2):
        """Compare textual content using TF-IDF"""
        if not text1.strip() or not text2.strip():
            return 0.0
        
        try:
            # Clean text
            text1_clean = re.sub(r'\s+', ' ', text1.strip())
            text2_clean = re.sub(r'\s+', ' ', text2.strip())
            
            # Vectorize and compare
            tfidf_matrix = self.vectorizer.fit_transform([text1_clean, text2_clean])
            similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
            
            return similarity
        except:
            return 0.0
    
    def _compare_links(self, links1, links2):
        """Compare link structures"""
        if not links1 or not links2:
            return 0.0
        
        # Compare link counts
        count_sim = 1 - abs(len(links1) - len(links2)) / max(len(links1), len(links2))
        
        # Compare common links
        common_links = set(links1).intersection(set(links2))
        link_sim = len(common_links) / max(len(set(links1)), len(set(links2)))
        
        return (count_sim + link_sim) / 2
    
    def detect_phishing_patterns(self, html_features):
        """Detect common phishing patterns in HTML"""
        warnings = []
        
        # Check for hidden form fields
        for form in html_features['forms']:
            for input_field in form['inputs']:
                if input_field['type'] == 'hidden' and 'password' in input_field.get('name', '').lower():
                    warnings.append("Hidden password field detected")
        
        # Check for external scripts
        external_scripts = [script for script in html_features['scripts'] if script and 'http' in script]
        if len(external_scripts) > 5:  # More than 5 external scripts
            warnings.append("Many external scripts detected")
        
        # Check for suspicious form actions
        for form in html_features['forms']:
            if form['action'] and not form['action'].startswith(('http', '#')):
                warnings.append("Suspicious form action")
        
        return warnings