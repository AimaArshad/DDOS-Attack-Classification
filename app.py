from flask import Flask,render_template,request, jsonify,json
import joblib
import numpy as np
import pandas as pd
import os

app=Flask(__name__)


from flask_cors import CORS
CORS(app)
# Load the trained models and scaler 

rf_model=joblib.load('rf_model.joblib')
lr_model=joblib.load('lr_model.joblib')
nn_model=joblib.load('nn_model.joblib')
scaler=joblib.load('scaler.joblib')

# Get feature names from your dataset (adjust based on your actual features)
# feature_names = X_train.columns.tolist()

# Load feature names
with open('feature_names.json','r') as f:
    feature_names=json.load(f)
    
    
    
@app.route('/')
def home():
  return render_template('index.html',features=feature_names)

@app.route('/predict',methods=['POST'])
def predict():
  try:
    #Get data from form
    input_data=[]
    for feature in feature_names:
      value=request.form.get(feature,0)
      input_data.append(float(value))
      
    #Convert to numpy array and reshape
    input_array=np.array(input_data).reshape(1,-1)
    
    #Scale the input
    input_scaled=scaler.transform(input_array)  
    
    #Make predictions
    rf_pred=rf_model.predict(input_scaled)
    lr_pred=lr_model.predict(input_scaled)
    nn_pred=nn_model.predict(input_scaled)
    
    # Get prediction probabilities
    rf_proba=rf_model.predict_proba(input_scaled)
    lr_proba=lr_model.predict_proba(input_scaled)
    nn_proba=nn_model.predict_proba(input_scaled)
    
    #PrepareResponse
    result={
      'random_forest':{
        
        'prediction':int(rf_pred[0]),
        'probability':float(rf_proba[0][1]),
        'label':'DDoS' if rf_pred[0]==1 else 'BENIGN'
      },
      
      'logistic_regression':{
        'prediction':int(lr_pred[0]),
        'probability': float(lr_proba[0][1]),
        'label':'DDoS' if lr_pred[0]==1 else 'BENIGN'
      },
       'neural_network': {
                'prediction': int(nn_pred[0]),
                'probability': float(nn_proba[0][1]),
                'label': 'DDoS' if nn_pred[0] == 1 else 'BENIGN'
      }    
    }
    
    return render_template('result.html',result=result,input_data=input_data,features=feature_names)
  except Exception as e:
    return render_template('error.html',error=str(e))  
  
  
@app.route('/api/predict',methods=['POST'])
def api_predict():
  try:
    data=request.get_json()
    input_data=[]
    
    for feature in feature_names:
      value=data.get(feature,0)
      input_data.append(float(value))
      
    # Convert to numpy array and reshape
    input_array = np.array(input_data).reshape(1, -1)  
    
    # Scale the input
    input_scaled = scaler.transform(input_array)
    
    # Make predictions
    rf_pred = rf_model.predict(input_scaled)
    lr_pred = lr_model.predict(input_scaled)
    nn_pred = nn_model.predict(input_scaled)
        
    # Get prediction probabilities
    rf_proba = rf_model.predict_proba(input_scaled)
    lr_proba = lr_model.predict_proba(input_scaled)
    nn_proba = nn_model.predict_proba(input_scaled)
    
   # Prepare response
    result = {
            'random_forest': {
                'prediction': int(rf_pred[0]),
                'probability': float(rf_proba[0][1]),
                'label': 'DDoS' if rf_pred[0] == 1 else 'BENIGN'
            },
            'logistic_regression': {
                'prediction': int(lr_pred[0]),
                'probability': float(lr_proba[0][1]),
                'label': 'DDoS' if lr_pred[0] == 1 else 'BENIGN'
            },
            'neural_network': {
                'prediction': int(nn_pred[0]),
                'probability': float(nn_proba[0][1]),
                'label': 'DDoS' if nn_pred[0] == 1 else 'BENIGN'
            }
    }
    
    return jsonify(result)
  except Exception as e:
    return jsonify({'error':str(e)})
  
if __name__=='__main__':
  app.run(debug=True)  











# .................................................................




# # app.py
# import os
# import pandas as pd
# import numpy as np
# from flask import Flask, request, render_template, jsonify, send_file
# from werkzeug.utils import secure_filename
# import pickle
# import pyshark
# import tempfile
# import json
# from datetime import datetime

# # Load your trained model (save it first)
# # rf_model.fit(X_train, y_train)
# # with open('ddos_model.pkl', 'wb') as f:
# #     pickle.dump(rf_model, f)

# app = Flask(__name__)
# app.config['UPLOAD_FOLDER'] = 'uploads'
# app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit
# app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng'}

# # Create upload directory if it doesn't exist
# os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# # Load the trained model
# def load_model():
#     with open('ddos_model.pkl', 'rb') as f:
#         model = pickle.load(f)
#     return model

# model = load_model()

# # Feature extraction from PCAP (simplified - you need to adapt to your actual features)
# def extract_features_from_pcap(pcap_path):
#     # This is a simplified feature extraction
#     # You need to implement the exact same features as your training data
    
#     # Placeholder for actual feature extraction
#     # In reality, you would extract all the features used during training
#     features = []
    
#     try:
#         # Using pyshark to analyze pcap
#         cap = pyshark.FileCapture(pcap_path)
        
#         # Initialize counters and statistics
#         packet_count = 0
#         packet_lengths = []
#         time_intervals = []
#         prev_time = None
        
#         # Protocol counters
#         tcp_count = 0
#         udp_count = 0
#         icmp_count = 0
        
#         for packet in cap:
#             packet_count += 1
            
#             # Get packet length
#             if hasattr(packet, 'length'):
#                 packet_lengths.append(int(packet.length))
            
#             # Get time interval
#             if hasattr(packet, 'sniff_time'):
#                 if prev_time is not None:
#                     time_intervals.append(float(packet.sniff_time.timestamp() - prev_time))
#                 prev_time = packet.sniff_time
            
#             # Count protocols
#             if hasattr(packet, 'transport_layer'):
#                 if packet.transport_layer == 'TCP':
#                     tcp_count += 1
#                 elif packet.transport_layer == 'UDP':
#                     udp_count += 1
#             elif hasattr(packet, 'icmp'):
#                 icmp_count += 1
        
#         cap.close()
        
#         # Calculate statistics (simplified - you need to match your training features)
#         if packet_lengths:
#             avg_packet_length = sum(packet_lengths) / len(packet_lengths)
#             max_packet_length = max(packet_lengths)
#             min_packet_length = min(packet_lengths)
#         else:
#             avg_packet_length = max_packet_length = min_packet_length = 0
            
#         if time_intervals:
#             avg_time_interval = sum(time_intervals) / len(time_intervals)
#             max_time_interval = max(time_intervals) if time_intervals else 0
#             min_time_interval = min(time_intervals) if time_intervals else 0
#         else:
#             avg_time_interval = max_time_interval = min_time_interval = 0
        
#         # Protocol percentages
#         if packet_count > 0:
#             tcp_percentage = tcp_count / packet_count
#             udp_percentage = udp_count / packet_count
#             icmp_percentage = icmp_count / packet_count
#         else:
#             tcp_percentage = udp_percentage = icmp_percentage = 0
        
#         # Create feature vector (THIS MUST MATCH YOUR TRAINING FEATURES)
#         # This is just an example - you need to implement the exact features from your training
#         features = [
#             packet_count,
#             avg_packet_length,
#             max_packet_length,
#             min_packet_length,
#             avg_time_interval,
#             max_time_interval,
#             min_time_interval,
#             tcp_percentage,
#             udp_percentage,
#             icmp_percentage
#             # Add all other features from your training data
#         ]
        
#     except Exception as e:
#         print(f"Error processing pcap: {e}")
    
#     return features

# def allowed_file(filename):
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/upload', methods=['POST'])
# def upload_file():
#     if 'file' not in request.files:
#         return jsonify({'error': 'No file part'})
    
#     file = request.files['file']
#     if file.filename == '':
#         return jsonify({'error': 'No selected file'})
    
#     if file and allowed_file(file.filename):
#         filename = secure_filename(file.filename)
#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#         file.save(filepath)
        
#         # Process the PCAP file
#         try:
#             features = extract_features_from_pcap(filepath)
            
#             # Convert to DataFrame with correct column names
#             # You need to ensure the feature names match your training data
#             feature_names = [
#                 'Packet_Count', 'Avg_Packet_Length', 'Max_Packet_Length', 
#                 'Min_Packet_Length', 'Avg_Time_Interval', 'Max_Time_Interval',
#                 'Min_Time_Interval', 'TCP_Percentage', 'UDP_Percentage', 'ICMP_Percentage'
#                 # Add all other feature names from your training data
#             ]
            
#             features_df = pd.DataFrame([features], columns=feature_names)
            
#             # Make prediction
#             prediction = model.predict(features_df)
#             prediction_proba = model.predict_proba(features_df)
            
#             # Interpret results
#             result = "DDoS Attack Detected" if prediction[0] == 1 else "Normal Traffic"
#             confidence = prediction_proba[0][1] if prediction[0] == 1 else prediction_proba[0][0]
            
#             # Prepare response
#             response = {
#                 'filename': filename,
#                 'prediction': result,
#                 'confidence': float(confidence),
#                 'timestamp': datetime.now().isoformat()
#             }
            
#             return jsonify(response)
            
#         except Exception as e:
#             return jsonify({'error': f'Error processing file: {str(e)}'})
    
#     return jsonify({'error': 'Invalid file type'})

# @app.route('/batch_predict', methods=['POST'])
# def batch_predict():
#     if 'files' not in request.files:
#         return jsonify({'error': 'No files part'})
    
#     files = request.files.getlist('files')
#     results = []
    
#     for file in files:
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)
#             filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             file.save(filepath)
            
#             try:
#                 features = extract_features_from_pcap(filepath)
                
#                 # Convert to DataFrame with correct column names
#                 feature_names = [
#                     'Packet_Count', 'Avg_Packet_Length', 'Max_Packet_Length', 
#                     'Min_Packet_Length', 'Avg_Time_Interval', 'Max_Time_Interval',
#                     'Min_Time_Interval', 'TCP_Percentage', 'UDP_Percentage', 'ICMP_Percentage'
#                     # Add all other feature names from your training data
#                 ]
                
#                 features_df = pd.DataFrame([features], columns=feature_names)
                
#                 # Make prediction
#                 prediction = model.predict(features_df)
#                 prediction_proba = model.predict_proba(features_df)
                
#                 # Interpret results
#                 result = "DDoS Attack" if prediction[0] == 1 else "Normal Traffic"
#                 confidence = prediction_proba[0][1] if prediction[0] == 1 else prediction_proba[0][0]
                
#                 results.append({
#                     'filename': filename,
#                     'prediction': result,
#                     'confidence': float(confidence),
#                     'timestamp': datetime.now().isoformat()
#                 })
                
#             except Exception as e:
#                 results.append({
#                     'filename': filename,
#                     'error': f'Error processing file: {str(e)}'
#                 })
    
#     return jsonify({'results': results})

# if __name__ == '__main__':
#     app.run(debug=True)